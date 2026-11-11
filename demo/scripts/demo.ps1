param(
    [ValidateSet("status", "drift", "reset")]
    [string]$Action = "status",
    [ValidateRange(1, 300)]
    [int]$ObserveSeconds = 30,
    [ValidateRange(5, 120)]
    [int]$ProbeSeconds = 30
)

# P10 drift walkthrough. KubeHeal remains in test mode, so its Executor cannot write.
# The script's only workload mutation is the reversible prod/victim-app CPU drift below.
$ErrorActionPreference = "Stop"
. "$PSScriptRoot\..\k3d\lib.ps1"
Initialize-Tools -SkipK3d -SkipHelm -SkipDocker
Set-Location $RepoRoot

function Assert-TestMode {
    $mode = (K get configmap kubeheal-mode -n kubeheal -o "jsonpath={.data.mode}").Trim()
    if ($mode -ne "test") {
        throw "Refusing to run: global kubeheal-mode is '$mode'. Set it to test first."
    }
    Write-Host "KubeHeal mode: test (Executor writes are blocked)."
}

function Set-CpuResources([string]$request, [string]$limit) {
    $patch = @(
        @{ op = "replace"; path = "/spec/template/spec/containers/0/resources/requests/cpu"; value = $request },
        @{ op = "replace"; path = "/spec/template/spec/containers/0/resources/limits/cpu"; value = $limit }
    ) | ConvertTo-Json -Compress
    K -n prod patch deployment victim-app --type=json -p $patch | Out-Host
    Wait-Rollout "prod" "deployment" "victim-app" 180
}

function Read-LatestAction {
    K exec redis-0 -n kubeheal '--' redis-cli XREVRANGE kubeheal.actions + - COUNT 1
}

function Prime-MetricWindow {
    $python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
    $verifier = Join-Path $RepoRoot "demo\scripts\verify_health_queries.py"
    if (-not (Test-Path $python)) { throw "Python venv not found at $python" }
    $oldPythonPath = $env:PYTHONPATH
    try {
        $env:PYTHONPATH = $RepoRoot
        & $python $verifier --namespace prod --seconds $ProbeSeconds
        if ($LASTEXITCODE -ne 0) { throw "Health-query verifier failed with exit code $LASTEXITCODE" }
    }
    finally {
        $env:PYTHONPATH = $oldPythonPath
    }
}

function Wait-CooldownExpired {
    $key = "kubeheal:cooldown:prod:victim-app"
    $deadline = [DateTime]::UtcNow.AddSeconds(330)
    while ([DateTime]::UtcNow -lt $deadline) {
        $ttlText = (K exec redis-0 -n kubeheal '--' redis-cli TTL $key).Trim()
        $ttl = 0
        if ([int]::TryParse($ttlText, [ref]$ttl) -and $ttl -gt 0) {
            Write-Host "Waiting for Health Agent cooldown ($ttl seconds remain)."
            Start-Sleep -Seconds ([Math]::Min(5, $ttl))
            continue
        }
        return
    }
    throw "Health Agent cooldown did not expire within 330 seconds."
}

function Show-Status {
    Assert-TestMode
    $request = (K get deployment victim-app -n prod -o "jsonpath={.spec.template.spec.containers[0].resources.requests.cpu}").Trim()
    $limit = (K get deployment victim-app -n prod -o "jsonpath={.spec.template.spec.containers[0].resources.limits.cpu}").Trim()
    $image = (K get deployment victim-app -n prod -o "jsonpath={.spec.template.spec.containers[0].image}").Trim()
    Write-Host "prod/victim-app request=$request limit=$limit image=$image"
    K get pods -n prod -l app.kubernetes.io/name=victim-app -o wide | Out-Host
    Write-Host "Latest Fusion action:"
    Read-LatestAction | Out-Host
}

function Reset-Victim {
    Assert-TestMode
    Set-CpuResources "100m" "500m"
    Write-Host "Restored prod/victim-app to request=100m, limit=500m."
}

try {
    switch ($Action) {
        "status" { Show-Status }
        "reset" { Reset-Victim }
        "drift" {
            Assert-TestMode
            Write-Host "Priming the victim metrics so each channel has live samples."
            Prime-MetricWindow
            Wait-CooldownExpired
            $previous = Read-LatestAction
            $previousId = if ($previous.Count -gt 0) { [string]$previous[0] } else { "" }
            try {
                Write-Host "Injecting prod/victim-app CPU request=50m and limit=50m."
                Set-CpuResources "50m" "50m"
                $deadline = [DateTime]::UtcNow.AddSeconds($ObserveSeconds)
                $latest = @()
                do {
                    Start-Sleep -Seconds 2
                    $latest = @(Read-LatestAction)
                    $latestId = if ($latest.Count -gt 0) { [string]$latest[0] } else { "" }
                } while ($latestId -eq $previousId -and [DateTime]::UtcNow -lt $deadline)
                if ($latestId -ne $previousId) {
                    Write-Host "Latest Fusion action (mode is test; inspect the action type and rationale):"
                    $latest | Out-Host
                } else {
                    Write-Warning "No new Fusion action appeared within $ObserveSeconds seconds. Check Health Agent and Fusion logs."
                }
            }
            finally {
                Write-Host "Resetting victim CPU request and limit."
                Set-CpuResources "100m" "500m"
            }
        }
    }
}
catch {
    Write-Error $_
    exit 1
}
