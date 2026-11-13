param([string]$Context = "k3d-kubeheal")
$ErrorActionPreference = "Stop"
$context = $Context
$namespace = "kubeheal"
$rootName = "kubeheal-minio-root"
$clientName = "kubeheal-minio-client"

$root = kubectl --context $context -n $namespace get secret $rootName --ignore-not-found -o name
if ($LASTEXITCODE -ne 0) { throw "Could not inspect the MinIO root Secret in $context/$namespace" }
$client = kubectl --context $context -n $namespace get secret $clientName --ignore-not-found -o name
if ($LASTEXITCODE -ne 0) { throw "Could not inspect the MinIO client Secret in $context/$namespace" }
if ($root -and $client) {
    Write-Output "MinIO credentials already exist in $context/$namespace."
    exit 0
}
if ($root -or $client) {
    throw "Only one MinIO Secret exists. Resolve the partial setup before continuing; no Secret was changed."
}

function New-RandomPassword {
    $random = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(48)
    return [Convert]::ToBase64String($random).TrimEnd("=")
}

function Apply-Secret([string]$name, [hashtable]$values) {
    $data = @{}
    foreach ($key in $values.Keys) {
        $data[$key] = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$values[$key]))
    }
    $manifest = @{
        apiVersion = "v1"
        kind = "Secret"
        metadata = @{ name = $name; namespace = $namespace }
        type = "Opaque"
        data = $data
    } | ConvertTo-Json -Depth 6 -Compress
    $manifest | kubectl --context $context apply -f - | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create MinIO Secret $name in $context/$namespace" }
}

Apply-Secret $rootName @{
    "root-user" = "kubehealminio"
    "root-password" = New-RandomPassword
}
Apply-Secret $clientName @{
    "access-key" = "kubehealledger"
    "secret-key" = New-RandomPassword
}
Write-Output "Generated MinIO root and ledger-client Secrets in $context/$namespace. Values were not printed."
