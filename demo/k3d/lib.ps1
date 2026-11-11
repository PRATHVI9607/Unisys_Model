# Shared helpers for the KubeHeal k3d demo scripts (demo branch only).
# Dot-source it:  . "$PSScriptRoot\lib.ps1"
# Safety: every kubectl and helm call goes through K / H below, which always pass --context k3d-kubeheal.
# Nothing here ever touches another cluster (the owner's `hybrid-demo` must never be used).

$ErrorActionPreference = "Stop"
$script:Context     = "k3d-kubeheal"
$script:ClusterName = "kubeheal"
$script:RegistryName = "kubeheal-registry"          # container name as created by k3d: kubeheal-registry
$script:RegistryHostPort = 5150                      # not 5111: that one belongs to the hybrid-demo cluster
$script:RegistryHost = "localhost:$($script:RegistryHostPort)"           # as seen from this machine
$script:RegistryInCluster = "$($script:RegistryName):5000"               # as seen from the nodes (k3d mirror)
$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$script:ImageTag = "v4"

# Pinned versions (chosen, not measured). Change here only.
$script:Versions = @{
    ExternalSnapshotter = "v8.2.0"
    CsiHostPath         = "v1.15.0"
    KubePrometheusStack = "65.5.1"
    PrometheusAdapter   = "4.11.0"
    K6Image             = "grafana/k6:0.54.0"
}

function Say([string]$msg)  { Write-Host "[kubeheal-demo] $msg" -ForegroundColor Cyan }
function Warn([string]$msg) { Write-Host "[kubeheal-demo] WARNING: $msg" -ForegroundColor Yellow }

function Find-Tool([string]$name, [string]$wingetDir) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $root = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages"
    if (Test-Path $root) {
        $hit = Get-ChildItem -Path (Join-Path $root "$wingetDir*") -Recurse -Filter "$name.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    throw "$name was not found on PATH or under the WinGet packages folder. Install it (winget install $wingetDir) and retry."
}

function Initialize-Tools {
    param(
        [switch]$SkipK3d,
        [switch]$SkipHelm,
        [switch]$SkipDocker
    )
    $script:KubectlExe = Find-Tool "kubectl" "Kubernetes.kubectl"
    if (-not $SkipK3d) { $script:K3dExe = Find-Tool "k3d" "k3d.k3d" }
    if (-not $SkipHelm) { $script:HelmExe = Find-Tool "helm" "Helm.Helm" }
    if (-not $SkipDocker) {
        $script:DockerExe = Find-Tool "docker" "Docker.DockerDesktop"
        & $script:DockerExe info --format '{{.ServerVersion}}' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Docker is not running." }
    }
}

# Native stderr is kept apart from stdout: kubectl/helm warnings must not end up in values that scripts compare
# (jsonpath results, HPA reads). Both streams are only joined in the error message.
function Split-NativeOutput($records) {
    $err = @($records | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { $_.ToString() })
    $out = @($records | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
    return @{ Out = $out; Err = $err }
}

# kubectl pinned to the demo cluster. Output goes to the pipeline, errors throw.
function K {
    # `$input` carries piped text (for example `... | K apply -f -`) to kubectl's stdin.
    $parts = Split-NativeOutput ($input | & $script:KubectlExe --context $script:Context @args 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "kubectl $($args -join ' ') failed: $(($parts.Err + $parts.Out) -join "`n")" }
    return $parts.Out
}
# kubectl that is allowed to fail (returns $null on failure).
function KTry {
    $parts = Split-NativeOutput ($input | & $script:KubectlExe --context $script:Context @args 2>&1)
    if ($LASTEXITCODE -ne 0) { return $null }
    return $parts.Out
}
function Hc {
    $parts = Split-NativeOutput (& $script:HelmExe --kube-context $script:Context @args 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "helm $($args -join ' ') failed: $(($parts.Err + $parts.Out) -join "`n")" }
    return $parts.Out
}
function Apply-Url([string]$url) {
    Say "apply $url"
    K apply --server-side --force-conflicts -f $url | Out-Null
}

function Fix-Kubeconfig {
    # k3d writes host.docker.internal into the kubeconfig, which this machine does not resolve: use 127.0.0.1.
    $port = (docker port "k3d-$($script:ClusterName)-serverlb" 6443/tcp) -replace '^.*:', ''
    if (-not $port) { throw "Could not find the published API port of k3d-$($script:ClusterName)-serverlb" }
    & $script:KubectlExe config set-cluster $script:Context --server "https://127.0.0.1:$port" | Out-Null
    $got = K get nodes -o name
    if (-not $got) { throw "The kubeconfig fix did not give a working connection" }
}

function Wait-Rollout([string]$ns, [string]$kind, [string]$name, [int]$timeoutSec = 300) {
    K -n $ns rollout status "$kind/$name" --timeout "$($timeoutSec)s" | Out-Null
}

function Assert-ClusterIsDemo {
    $cur = & $script:KubectlExe config get-contexts -o name
    if ($cur -notcontains $script:Context) { throw "Context $($script:Context) does not exist; run up.ps1 first." }
}
