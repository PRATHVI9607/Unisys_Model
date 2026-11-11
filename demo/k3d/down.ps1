# Remove the KubeHeal demo cluster (demo branch only). Deletes ONLY the cluster named `kubeheal` and its registry.
#   .\demo\k3d\down.ps1
. "$PSScriptRoot\lib.ps1"
Initialize-Tools

$exists = (& $K3dExe cluster list -o json | ConvertFrom-Json | Where-Object { $_.name -eq $ClusterName })
if (-not $exists) { Say "cluster $ClusterName does not exist, nothing to do"; return }
Say "deleting cluster $ClusterName (other clusters, for example hybrid-demo, are not touched)"
& $K3dExe cluster delete $ClusterName
if ($LASTEXITCODE -ne 0) { throw "k3d cluster delete failed" }
# the registry created with the cluster is removed by k3d; remove a leftover only if it is ours
$left = docker ps -a --filter "name=^/$RegistryName$" --format '{{.Names}}'
if ($left -eq $RegistryName) { docker rm -f $RegistryName | Out-Null }
Say "done"
