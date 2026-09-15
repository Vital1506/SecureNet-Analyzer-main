# SecureNet Analyzer launcher (PowerShell).
# Forwards all arguments to Main.py.
#
# Quick examples:
#   .un.ps1 block --list-blocks --offline
#   .un.ps1 block-activate --dry-run
#   .un.ps1 intel --intel-source sample --intel-auto-block
#   .un.ps1 c --pc 50 --summary --alert-on 50 --alert-file alerts.log

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

python .\Main.py @Args
