# Create (or complete) the KubeHeal demo environment on k3d. Demo branch only. Safe to run again.
#   .\demo\k3d\up.ps1                 everything
#   .\demo\k3d\up.ps1 -SkipImages     reuse the images from the last images.ps1 run
#   .\demo\k3d\up.ps1 -Stage csi      run one stage: cluster, csi, monitoring, images, install, adapter, victim, falco
# The cluster is always `kubeheal` and every kubectl/helm call uses --context k3d-kubeheal (see lib.ps1).
# Nothing here touches any other cluster.
param(
    [switch]$SkipImages,
    [string]$Stage = "all"
)

. "$PSScriptRoot\lib.ps1"
Initialize-Tools
Set-Location $RepoRoot

function Want([string]$s) { return ($Stage -eq "all") -or ($Stage -eq $s) }
$sw = [Diagnostics.Stopwatch]::StartNew()

# ---------------------------------------------------------------- cluster
if (Want "cluster") {
    $exists = (& $K3dExe cluster list -o json | ConvertFrom-Json | Where-Object { $_.name -eq $ClusterName })
    if (-not $exists) {
        Say "creating cluster $ClusterName (1 server, 2 agents, registry $RegistryHost)"
        & $K3dExe cluster create $ClusterName --servers 1 --agents 2 -p "8080:80@loadbalancer" `
            --registry-create "$($RegistryName):0.0.0.0:$RegistryHostPort" --wait --timeout 240s
        if ($LASTEXITCODE -ne 0) { throw "k3d cluster create failed" }
    } else {
        Say "cluster $ClusterName already exists"
        & $K3dExe cluster start $ClusterName 2>&1 | Out-Null
    }
    Fix-Kubeconfig
    K get nodes | Out-Host
    # The CSI hostpath driver is one pod: its volumes exist on one node. Mark that node and pin workloads with volumes to it.
    K label node k3d-kubeheal-agent-0 kubeheal-demo/storage=true --overwrite | Out-Null
}

# ---------------------------------------------------------------- snapshots: CRDs, controller, CSI hostpath driver
if (Want "csi") {
    $csi = Join-Path $PSScriptRoot "csi"
    Say "VolumeSnapshot CRDs and snapshot-controller (external-snapshotter $($Versions.ExternalSnapshotter))"
    foreach ($f in "snapshot.storage.k8s.io_volumesnapshotclasses.yaml", "snapshot.storage.k8s.io_volumesnapshotcontents.yaml", "snapshot.storage.k8s.io_volumesnapshots.yaml") {
        K apply --server-side --force-conflicts -f (Join-Path $csi $f) | Out-Null
    }
    K apply --server-side --force-conflicts -f (Join-Path $csi "rbac-snapshot-controller.yaml") | Out-Null
    K apply --server-side --force-conflicts -f (Join-Path $csi "setup-snapshot-controller.yaml") | Out-Null
    Say "CSI hostpath driver $($Versions.CsiHostPath)"
    foreach ($f in "rbac-provisioner.yaml", "rbac-attacher.yaml", "rbac-snapshotter.yaml", "rbac-resizer.yaml", "rbac-health-monitor.yaml",
                   "csi-hostpath-driverinfo.yaml", "csi-hostpath-plugin.yaml", "csi-storageclass.yaml") {
        K apply --server-side --force-conflicts -f (Join-Path $csi $f) | Out-Null
    }
    # one plugin pod on the storage node (see victim.yaml)
    K -n default patch statefulset csi-hostpathplugin --type merge -p '{"spec":{"template":{"spec":{"nodeSelector":{"kubeheal-demo/storage":"true"}}}}}' | Out-Null
    Wait-Rollout "default" "statefulset" "csi-hostpathplugin" 300
    Wait-Rollout "kube-system" "deployment" "snapshot-controller" 300
    # exact name expected by the Executor (SNAPSHOT_CLASS)
    K apply -f (Join-Path $csi "csi-hostpath-snapshotclass.yaml") | Out-Null
    $cls = K get volumesnapshotclass csi-hostpath-snapclass -o name
    Say "snapshot class present: $cls"
}

# ---------------------------------------------------------------- monitoring: Prometheus, Grafana
if (Want "monitoring") {
    Say "kube-prometheus-stack $($Versions.KubePrometheusStack) in namespace monitoring"
    Hc repo add prometheus-community https://prometheus-community.github.io/helm-charts --force-update | Out-Null
    Hc repo update | Out-Null
    Hc upgrade --install monitoring prometheus-community/kube-prometheus-stack --version $Versions.KubePrometheusStack `
        -n monitoring --create-namespace -f (Join-Path $PSScriptRoot "values-monitoring.yaml") --wait --timeout 10m | Out-Null
    # Grafana dashboard from the repo (picked up by the sidecar through the label)
    $dash = Join-Path $RepoRoot "deploy\grafana\kubeheal-overview.json"
    K -n monitoring create configmap kubeheal-grafana-dashboard "--from-file=kubeheal-overview.json=$dash" --dry-run=client -o yaml | K apply -f - | Out-Null
    K -n monitoring label configmap kubeheal-grafana-dashboard grafana_dashboard=1 --overwrite | Out-Null
    Say "Prometheus: prometheus-operated.monitoring.svc.cluster.local:9090"
}

# ---------------------------------------------------------------- images
if ((Want "images") -and -not $SkipImages) {
    & "$PSScriptRoot\images.ps1"
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) { throw "images.ps1 failed" }
}

# ---------------------------------------------------------------- KubeHeal chart
function New-UrlSafeSecret { -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ }) }
function Ensure-Secret([string]$name, [hashtable]$literals) {
    if (KTry -n kubeheal get secret $name -o name) { return }
    $args = @("-n", "kubeheal", "create", "secret", "generic", $name)
    foreach ($k in $literals.Keys) { $args += "--from-literal=$k=$($literals[$k])" }
    K @args | Out-Null
}
if (Want "install") {
    $gen = Join-Path $PSScriptRoot ".generated-values.yaml"
    if (-not (Test-Path $gen)) { throw "No built images: run .\demo\k3d\images.ps1 first." }
    K create namespace kubeheal --dry-run=client -o yaml | K apply -f - | Out-Null
    $tokenFile = Join-Path $PSScriptRoot ".admin-token"
    if (-not (Test-Path $tokenFile)) { Set-Content -Path $tokenFile -Value (New-UrlSafeSecret) -Encoding ascii }
    Ensure-Secret "kubeheal-dashboard-admin" @{ token = (Get-Content $tokenFile -Raw).Trim() }
    Ensure-Secret "kubeheal-redis" @{ password = (New-UrlSafeSecret) }
    & "$RepoRoot\scripts\minio_secret.ps1"
    Say "helm install kubeheal (values-k3d-demo.yaml + generated image values)"
    Hc upgrade --install kubeheal (Join-Path $RepoRoot "deploy\helm\kubeheal") -n kubeheal `
        -f (Join-Path $RepoRoot "deploy\helm\kubeheal\values-k3d-demo.yaml") -f $gen --wait --timeout 10m | Out-Null
    K -n kubeheal get pods | Out-Host
}

# ---------------------------------------------------------------- prometheus-adapter (queue-depth HPA)
if (Want "adapter") {
    $ruleYaml = K -n kubeheal get configmap kubeheal-prometheus-adapter-rule -o "jsonpath={.data.rule\.yaml}"
    if (-not $ruleYaml) { throw "ConfigMap kubeheal-prometheus-adapter-rule is missing: install the chart first" }
    # rule.yaml is a YAML list; indent it under rules.custom
    $indented = ($ruleYaml -split "`n" | ForEach-Object { "    $_" }) -join "`n"
    $values = @"
prometheus:
  url: http://prometheus-operated.monitoring.svc
  port: 9090
rules:
  default: false
  custom:
$indented
"@
    $vf = Join-Path $env:TEMP "kubeheal-adapter-values.yaml"
    Set-Content -Path $vf -Value $values -Encoding utf8
    Say "prometheus-adapter $($Versions.PrometheusAdapter)"
    Hc upgrade --install prometheus-adapter prometheus-community/prometheus-adapter --version $Versions.PrometheusAdapter `
        -n monitoring -f $vf --wait --timeout 5m | Out-Null
}

# ---------------------------------------------------------------- victim apps
if (Want "victim") {
    $tags = Get-Content (Join-Path $PSScriptRoot ".image-tags.json") -Raw | ConvertFrom-Json
    $img = "$RegistryInCluster/kubeheal/victim-app:$($tags.'victim-app')"
    Say "victim apps from $img"
    (Get-Content (Join-Path $PSScriptRoot "victim.yaml") -Raw).Replace("__IMAGE__", $img) | K apply -f - | Out-Null
    Wait-Rollout "prod" "deployment" "victim-app" 300
    Wait-Rollout "dev" "deployment" "victim-app" 300
}

Say "stage '$Stage' finished in $([int]$sw.Elapsed.TotalSeconds) s"
