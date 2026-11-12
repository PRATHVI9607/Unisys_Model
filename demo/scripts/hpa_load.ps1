#Requires -Version 7.0
param(
    [ValidateRange(1, 64)] [int]$Vus = 32,
    [ValidateRange(30, 300)] [int]$DurationSeconds = 90,
    [ValidateRange(5, 30)] [int]$SampleSeconds = 10,
    [ValidateRange(60, 600)] [int]$ScaleDownWaitSeconds = 330
)

# P10 D-8: bounded scoring load on the queue-depth HPA. The Job has no Kubernetes credentials;
# its narrowly scoped temporary NetworkPolicy only admits it to the inference service scoring port (POST /v1/health/predict).
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\k3d\lib.ps1"
Initialize-Tools -SkipK3d -SkipHelm -SkipDocker
Set-Location $RepoRoot

function Assert-TestMode {
    $mode = ([string](K get configmap kubeheal-mode -n kubeheal -o 'jsonpath={.data.mode}')).Trim()
    if ($mode -ne 'test') { throw "Refusing load run: kubeheal-mode is '$mode', expected test." }
}

function Read-Hpa {
    $replicas = K -n kubeheal get hpa kubeheal-inference `
        -o 'jsonpath=current={.status.currentReplicas} desired={.status.desiredReplicas} metric={.status.currentMetrics[0].pods.current.averageValue}'
    Write-Host "$(Get-Date -Format o) $replicas"
}

function KText([string[]]$kubectlArgs) {
    $value = K @kubectlArgs
    return (@($value) -join '').Trim()
}

$scriptPath = Join-Path $PSScriptRoot 'k6_health_model.js'
$runId = [Guid]::NewGuid().ToString('N')
$cmName = "kubeheal-k6-script-$runId"
$policyName = "kubeheal-k6-net-$runId"
$jobName = "kubeheal-k6-load-$runId"
$cmPath = Join-Path $env:TEMP "kubeheal-k6-script-$runId.yaml"
$policyPath = Join-Path $env:TEMP "kubeheal-k6-networkpolicy-$runId.yaml"
$jobPath = Join-Path $env:TEMP "kubeheal-k6-job-$runId.yaml"
$duration = "${DurationSeconds}s"

function Remove-RunResource([string]$kind, [string]$name, [string]$runId) {
    # Names include a per-invocation UUID; the label check ensures this invocation owns the resource.
    # Each call is best effort so an API error never skips later resources or local temp-file removal.
    try {
        $raw = KText @('-n', 'kubeheal', 'get', $kind, $name, '-o', 'json')
        if (-not $raw) { return }
        $resource = $raw | ConvertFrom-Json -AsHashtable
        if ($resource.metadata.labels['kubeheal.k8s.io/run-id'] -ne $runId) {
            Write-Warning "Leaving $kind/$name in place because its run-id label does not match this invocation."
            return
        }
        K -n kubeheal delete $kind $name --ignore-not-found | Out-Host
    } catch {
        $message = $_.Exception.Message
        if ($message -match '(?i)not.?found') { return }
        Write-Warning "Could not clean up $kind/$name for run ${runId}: $message"
    }
}

try {
    Assert-TestMode
    # Build a ConfigMap manifest directly so it can carry the ownership label. kubectl create
    # configmap does not support --labels on all installed kubectl versions. binaryData preserves
    # the exact JavaScript bytes and avoids PowerShell flattening newlines.
    $scriptBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($scriptPath))
    $configMap = @"
apiVersion: v1
kind: ConfigMap
metadata:
  name: $cmName
  namespace: kubeheal
  labels:
    kubeheal.k8s.io/run-id: $runId
binaryData:
  health.js: $scriptBase64
"@
    Set-Content -LiteralPath $cmPath -Value $configMap -Encoding utf8

$policy = @"
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: $policyName
  namespace: kubeheal
  labels:
    kubeheal.k8s.io/run-id: $runId
spec:
  podSelector:
    matchLabels: {app: kubeheal-inference}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: kubeheal-k6
              kubeheal.k8s.io/run-id: $runId
      ports:
        - {protocol: TCP, port: 8000}
"@
    Set-Content -LiteralPath $policyPath -Value $policy -Encoding utf8

    $job = @"
apiVersion: batch/v1
kind: Job
metadata:
  name: $jobName
  namespace: kubeheal
  labels:
    kubeheal.k8s.io/run-id: $runId
spec:
  backoffLimit: 0
  activeDeadlineSeconds: $($DurationSeconds + 60)
  template:
    metadata:
      labels:
        app: kubeheal-k6
        kubeheal.k8s.io/run-id: $runId
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                topologyKey: kubernetes.io/hostname
                labelSelector:
                  matchLabels: {app: kubeheal-inference}
      containers:
        - name: k6
          image: grafana/k6:0.54.0
          imagePullPolicy: IfNotPresent
          command: ["k6", "run", "/scripts/health.js"]
          env:
            - {name: K6_VUS, value: "$Vus"}
            - {name: K6_DURATION, value: "$duration"}
          resources:
            requests: {cpu: 100m, memory: 128Mi}
            limits: {cpu: 500m, memory: 256Mi}
          volumeMounts:
            - {name: script, mountPath: /scripts, readOnly: true}
      volumes:
        - name: script
          configMap: {name: $cmName}
"@
    Set-Content -LiteralPath $jobPath -Value $job -Encoding utf8

    Assert-TestMode
    Write-Host 'Waiting for HPA baseline current=2 desired=2:'
    $baselineDeadline = [DateTime]::UtcNow.AddSeconds($ScaleDownWaitSeconds)
    do {
        Read-Hpa
        $baselineCurrent = KText @('-n', 'kubeheal', 'get', 'hpa', 'kubeheal-inference',
            '-o', 'jsonpath={.status.currentReplicas}')
        $baselineDesired = KText @('-n', 'kubeheal', 'get', 'hpa', 'kubeheal-inference',
            '-o', 'jsonpath={.status.desiredReplicas}')
        if ($baselineCurrent -eq '2' -and $baselineDesired -eq '2') { break }
        Start-Sleep -Seconds $SampleSeconds
    } while ([DateTime]::UtcNow -lt $baselineDeadline)
    if ($baselineCurrent -ne '2' -or $baselineDesired -ne '2') {
        throw "HPA did not return to baseline within $ScaleDownWaitSeconds seconds (current=$baselineCurrent desired=$baselineDesired)."
    }
    Write-Host 'HPA baseline confirmed.'
    # `create` refuses to adopt/update an existing object. The UUID names and run-id labels let cleanup
    # distinguish these resources from anything created by another invocation or operator.
    K create -f $cmPath | Out-Host
    K create -f $policyPath | Out-Host
    $endpointDeadline = [DateTime]::UtcNow.AddSeconds(120)
    do {
        $endpoints = KText @('-n', 'kubeheal', 'get', 'endpoints', 'kubeheal-inference',
            '-o', 'jsonpath={.subsets[*].addresses[*].ip}')
        if ($endpoints) { break }
        Start-Sleep -Seconds 3
    } while ([DateTime]::UtcNow -lt $endpointDeadline)
    if (-not $endpoints) { throw 'Inference Service has no ready endpoints; refusing to start k6.' }
    Write-Host "Inference ready endpoints: $endpoints"
    K create -f $jobPath | Out-Host
    Write-Host 'HPA before load:'
    Read-Hpa

    $deadline = [DateTime]::UtcNow.AddSeconds($DurationSeconds + 60)
    $jobSucceeded = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds $SampleSeconds
        Write-Host 'HPA during load:'
        Read-Hpa
        $complete = KText @('-n', 'kubeheal', 'get', 'job', $jobName,
            '-o', 'jsonpath={.status.succeeded}')
        if ($complete -eq '1') { $jobSucceeded = $true; break }
        $failed = KText @('-n', 'kubeheal', 'get', 'job', $jobName,
            '-o', 'jsonpath={.status.failed}')
        if ($failed -eq '1') { throw "k6 Job failed; inspect kubectl logs for $jobName." }
    }
    if (-not $jobSucceeded) { throw "k6 Job did not complete within $($DurationSeconds + 60) seconds." }
    K -n kubeheal logs "job/$jobName" | Out-Host
    Write-Host 'HPA immediately after load:'
    Read-Hpa

    $scaleDownDeadline = [DateTime]::UtcNow.AddSeconds($ScaleDownWaitSeconds)
    do {
        Start-Sleep -Seconds $SampleSeconds
        Read-Hpa
        $current = KText @('-n', 'kubeheal', 'get', 'hpa', 'kubeheal-inference',
            '-o', 'jsonpath={.status.currentReplicas}')
        $desired = KText @('-n', 'kubeheal', 'get', 'hpa', 'kubeheal-inference',
            '-o', 'jsonpath={.status.desiredReplicas}')
        if ($current -eq '2' -and $desired -eq '2') { break }
    } while ([DateTime]::UtcNow -lt $scaleDownDeadline)
    if ($current -ne '2' -or $desired -ne '2') {
        throw "HPA did not return to baseline within $ScaleDownWaitSeconds seconds (current=$current desired=$desired)."
    }
}
catch {
    Write-Host 'k6 Job diagnostics:'
    KTry -n kubeheal get job $jobName -o yaml | Out-Host
    KTry -n kubeheal get pods -l "kubeheal.k8s.io/run-id=$runId" -o wide | Out-Host
    KTry -n kubeheal logs "job/$jobName" --all-containers=true --tail=100 | Out-Host
    throw
}
finally {
    Remove-RunResource 'job' $jobName $runId
    Remove-RunResource 'networkpolicy' $policyName $runId
    Remove-RunResource 'configmap' $cmName $runId
    try {
        Remove-Item -LiteralPath $cmPath, $policyPath, $jobPath -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Could not remove local k6 staging files for run ${runId}: $($_.Exception.Message)"
    }
}
