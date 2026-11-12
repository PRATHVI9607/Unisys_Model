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

Assert-TestMode
$scriptPath = Join-Path $PSScriptRoot 'k6_health_model.js'
$cmPath = Join-Path $env:TEMP 'kubeheal-k6-script.yaml'
$policyPath = Join-Path $env:TEMP 'kubeheal-k6-networkpolicy.yaml'
$jobPath = Join-Path $env:TEMP 'kubeheal-k6-job.yaml'
$duration = "${DurationSeconds}s"

# Let kubectl encode the file as ConfigMap data. Out-String -NoNewline flattened every JS line,
# causing the first // comment to consume the exports and k6 to report "no exported functions".
K create configmap kubeheal-k6-health-load -n kubeheal "--from-file=health.js=$scriptPath" `
    --dry-run=client -o yaml | Set-Content -LiteralPath $cmPath -Encoding utf8

$policy = @'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kubeheal-k6-health-load
  namespace: kubeheal
spec:
  podSelector:
    matchLabels: {app: kubeheal-inference}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels: {app: kubeheal-k6}
      ports:
        - {protocol: TCP, port: 8000}
'@
Set-Content -LiteralPath $policyPath -Value $policy -Encoding utf8

$job = @"
apiVersion: batch/v1
kind: Job
metadata:
  name: kubeheal-k6-health-load
  namespace: kubeheal
spec:
  backoffLimit: 0
  activeDeadlineSeconds: $($DurationSeconds + 60)
  template:
    metadata:
      labels: {app: kubeheal-k6}
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
          configMap: {name: kubeheal-k6-health-load}
"@
Set-Content -LiteralPath $jobPath -Value $job -Encoding utf8

$jobStarted = $false
try {
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
    K apply -f $cmPath | Out-Host
    K apply -f $policyPath | Out-Host
    $endpointDeadline = [DateTime]::UtcNow.AddSeconds(120)
    do {
        $endpoints = KText @('-n', 'kubeheal', 'get', 'endpoints', 'kubeheal-inference',
            '-o', 'jsonpath={.subsets[*].addresses[*].ip}')
        if ($endpoints) { break }
        Start-Sleep -Seconds 3
    } while ([DateTime]::UtcNow -lt $endpointDeadline)
    if (-not $endpoints) { throw 'Inference Service has no ready endpoints; refusing to start k6.' }
    Write-Host "Inference ready endpoints: $endpoints"
    $jobStarted = $true   # set first so a partial apply is still cleaned up in finally
    K apply -f $jobPath | Out-Host
    Write-Host 'HPA before load:'
    Read-Hpa

    $deadline = [DateTime]::UtcNow.AddSeconds($DurationSeconds + 60)
    $jobSucceeded = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds $SampleSeconds
        Write-Host 'HPA during load:'
        Read-Hpa
        $complete = KText @('-n', 'kubeheal', 'get', 'job', 'kubeheal-k6-health-load',
            '-o', 'jsonpath={.status.succeeded}')
        if ($complete -eq '1') { $jobSucceeded = $true; break }
        $failed = KText @('-n', 'kubeheal', 'get', 'job', 'kubeheal-k6-health-load',
            '-o', 'jsonpath={.status.failed}')
        if ($failed -eq '1') { throw 'k6 Job failed; inspect kubectl logs for kubeheal-k6-health-load.' }
    }
    if (-not $jobSucceeded) { throw "k6 Job did not complete within $($DurationSeconds + 60) seconds." }
    K -n kubeheal logs job/kubeheal-k6-health-load | Out-Host
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
}
catch {
    Write-Host 'k6 Job diagnostics:'
    KTry -n kubeheal get job kubeheal-k6-health-load -o yaml | Out-Host
    KTry -n kubeheal get pods -l app=kubeheal-k6 -o wide | Out-Host
    KTry -n kubeheal logs job/kubeheal-k6-health-load --all-containers=true --tail=100 | Out-Host
    throw
}
finally {
    if ($jobStarted) {
        K -n kubeheal delete job kubeheal-k6-health-load --ignore-not-found | Out-Host
    }
    K -n kubeheal delete networkpolicy kubeheal-k6-health-load --ignore-not-found | Out-Host
    K -n kubeheal delete configmap kubeheal-k6-health-load --ignore-not-found | Out-Host
    Remove-Item -LiteralPath $cmPath, $policyPath, $jobPath -Force -ErrorAction SilentlyContinue
}
