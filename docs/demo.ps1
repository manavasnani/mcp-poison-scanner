# Demo for a terminal recording. Run from the repository root:  .\docs\demo.ps1
# Uses only this repository's own fixture snapshots: nothing is launched and nothing leaves the machine.

$py = ".\.venv\Scripts\python.exe"
$lock = Join-Path $env:TEMP "mcp-poison-demo.lock.json"
if (Test-Path $lock) { Remove-Item $lock -Confirm:$false }

function Step($text, [scriptblock]$command) {
    Write-Host ""
    Write-Host "> $text" -ForegroundColor Cyan
    Start-Sleep -Seconds 1
    & $command
    Write-Host "exit code: $LASTEXITCODE" -ForegroundColor DarkGray
    Start-Sleep -Seconds 3
}

Step "scan an honest server" {
    & $py -m scanner.cli scan -s fixtures/snapshots/clean.json
}
Step "scan a poisoned server (first findings)" {
    # Run to the end first, so the exit code shown is the scan's own.
    $lines = & $py -m scanner.cli scan -s fixtures/snapshots/poisoned.json
    $lines | Select-Object -First 22
}
Step "approve a server while it is honest" {
    & $py -m scanner.cli pin -s fixtures/snapshots/rugpull_v1.json --name facts --lock $lock
}
Step "scan it again after it changed" {
    & $py -m scanner.cli scan -s fixtures/snapshots/rugpull_v2.json --name facts --lock $lock
}

Remove-Item $lock -Confirm:$false
