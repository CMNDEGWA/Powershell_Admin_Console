
$ErrorActionPreference = 'Stop'

[pscustomobject]@{
    message = 'PowerShell task completed'
    powershellVersion = $PSVersionTable.PSVersion.ToString()
    platform = [System.Environment]::OSVersion.Platform.ToString()
} | ConvertTo-Json -Compress

exit 0
