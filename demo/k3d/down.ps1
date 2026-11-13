# Remove the KubeHeal demo cluster (demo branch only). Deletes ONLY the cluster named `kubeheal` and its registry.
#   .\demo\k3d\down.ps1          asks you to type the cluster name first
#   .\demo\k3d\down.ps1 -Yes     no prompt (scripts)
# This destroys every volume in the cluster: the victim PVCs, MinIO and the audit ledger, Redis.
param(
    [switch]$Yes,
    [ValidatePattern('^[a-z0-9][a-z0-9-]{0,39}$')]
    [string]$ClusterName = "kubeheal",
    [ValidateRange(0, 65535)]
    [int]$RegistryHostPort = 0
)

. "$PSScriptRoot\lib.ps1"
if ($RegistryHostPort -eq 0) { $RegistryHostPort = if ($ClusterName -eq "kubeheal") { 5150 } else { 5151 } }
$script:ClusterName = $ClusterName
$script:Context = "k3d-$ClusterName"
$script:RegistryName = "$ClusterName-registry"
$script:RegistryHostPort = $RegistryHostPort
Initialize-Tools -SkipHelm

$exists = (& $K3dExe cluster list -o json | ConvertFrom-Json | Where-Object { $_.name -eq $ClusterName })
if (-not $exists) { Say "cluster $ClusterName does not exist, nothing to do"; return }
if (-not $Yes) {
    $answer = Read-Host "This deletes cluster '$ClusterName' with all its volumes (ledger, MinIO, victim data). Type the cluster name to continue"
    if ($answer -ne $ClusterName) { Say "not confirmed, nothing deleted"; return }
}
Say "deleting cluster $ClusterName (other clusters, for example hybrid-demo, are not touched)"
& $K3dExe cluster delete $ClusterName
if ($LASTEXITCODE -ne 0) { throw "k3d cluster delete failed" }
# the registry created with the cluster is removed by k3d; remove a leftover only if it is ours
$left = docker ps -a --filter "name=^/$RegistryName$" --format '{{.Names}}'
if ($left -eq $RegistryName) { docker rm -f $RegistryName | Out-Null }
Say "done"
