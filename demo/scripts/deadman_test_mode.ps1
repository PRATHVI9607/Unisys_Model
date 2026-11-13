# Independent safety switch for scripted enforce windows. It can only set k3d-kubeheal to test.
# Launch in a separate hidden PowerShell process and retain its output log with the run evidence.
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{32}$')]
    [string]$RunId,
    [ValidateRange(30, 1800)]
    [int]$AfterSeconds = 300
)

$ErrorActionPreference = 'Stop'
$context = 'k3d-kubeheal'
$namespace = 'kubeheal'
$started = [DateTime]::UtcNow
Write-Output "DEAD-MAN START run=$RunId context=$context started_utc=$($started.ToString('o')) timeout_s=$AfterSeconds"
$deadline = $started.AddSeconds($AfterSeconds)
$seenEnforce = $false
$endedBy = 'timeout'
while ([DateTime]::UtcNow -lt $deadline) {
    $modeRead = & kubectl --context $context -n $namespace get configmap kubeheal-mode -o 'jsonpath={.data.mode}' 2>&1
    $readCode = $LASTEXITCODE
    $mode = if ($readCode -eq 0) { ([string]$modeRead).Trim() } else { '' }
    if ($mode -eq 'enforce') {
        $seenEnforce = $true
    } elseif ($mode -eq 'test') {
        if ($seenEnforce) {
            $endedBy = 'mode_returned_to_test'
            break
        }
    } else {
        Write-Output "DEAD-MAN ACTION run=$RunId mode=$(if($mode){$mode}else{'unreadable'}); forcing test"
        & kubectl --context $context -n $namespace patch configmap kubeheal-mode --type merge `
            -p '{"data":{"mode":"test"}}' 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "dead-man could not set mode test for run $RunId" }
        $endedBy = 'fail_safe'
        break
    }
    Start-Sleep -Seconds 1
}

$verified = & kubectl --context $context -n $namespace get configmap kubeheal-mode -o 'jsonpath={.data.mode}' 2>&1
if ($LASTEXITCODE -ne 0 -or ([string]$verified).Trim() -ne 'test') {
    Write-Output "DEAD-MAN ACTION run=$RunId timeout_or_unreadable; forcing test"
    & kubectl --context $context -n $namespace patch configmap kubeheal-mode --type merge `
        -p '{"data":{"mode":"test"}}' 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "dead-man could not set mode test for run $RunId" }
    $verified = & kubectl --context $context -n $namespace get configmap kubeheal-mode -o 'jsonpath={.data.mode}' 2>&1
    if ($LASTEXITCODE -ne 0 -or ([string]$verified).Trim() -ne 'test') {
        throw "dead-man could not verify test mode for run $RunId"
    }
} elseif ($endedBy -eq 'timeout' -and -not $seenEnforce) {
    Write-Output "DEAD-MAN NOTE run=$RunId timed out before observing enforce; mode already test"
}
Write-Output "DEAD-MAN END run=$RunId ended_utc=$([DateTime]::UtcNow.ToString('o')) mode=test ended_by=$endedBy"
