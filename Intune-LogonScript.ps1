function Write-Log {
    Param(
        [string]$Value,
        [string]$Severity,
        [string]$Component = "CD4Intune",
        [string]$FileName = "CD4Intune.log"
    )
    $LogFilePath = "C:\Windows\Logs" + "\" + $FileName
    $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
    $Date = (Get-Date -Format "MM-dd-yyyy")
    $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""$($Component)"" context=""SYSTEM"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
    try {
        Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop 
    }
    catch [System.Exception] {
        Write-Warning -Message "Unable to append log entry to $FileName file. Error message: $($_.Exception.Message)"
    }
}

$ChocoConfFile = "C:\Windows\Temp\ChocoConf.json"
$ChocoBin = $env:ProgramData + "\Chocolatey\bin\choco.exe"

if (!(Test-Path -Path $ChocoBin)) {
    Write-Log -Value "$ChocoBin not detected; starting installation of chocolatey" -Severity 1 -Component "Invoke-Chocolatey"
    try {
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
    catch {
        Write-Log -Value "Failed to install chocolatey" -Severity 3 -Component "Invoke-Chocolatey"
    }
}

Write-Log -Value "Upgrading chocolatey and all existing packages" -Severity 1 -Component "Invoke-Chocolatey"
try {
    Invoke-Expression "cmd /c $ChocoBin upgrade all -y" -ErrorAction Stop
}
catch {
    Write-Log -Value "Failed to upgrade chocolatey and all existing packages" -Severity 3 -Component "Invoke-Chocolatey"
}

Write-Log -Value "Downloading config file" -Severity 1 -Component "Invoke-Chocolatey"
try {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Forsbakk/Intune/master/cfg/Choco/config.json" -OutFile $ChocoConfFile
}
catch {
    Write-Log -Value "Failed to download config file" -Severity 3 -Component "Invoke-Chocolatey"
    throw
}

$ChocoConf = Get-Content -Path $ChocoConfFile | ConvertFrom-Json

ForEach ($ChockoPkg in $ChocoConf) {
    Write-Log -Value "Running $($ChockoPkg.Mode) on $($ChockoPkg.Name)" -Severity 1 -Component "Invoke-Chocolatey"
    try {
        Invoke-Expression "cmd /c $ChocoBin $($ChockoPkg.Mode) $($ChockoPkg.Name) -y" -ErrorAction Stop
    }
    catch {
        Write-Log -Value "Failed to run $($ChockoPkg.Mode) on $($ChockoPkg.Name)" -Severity 3 -Component "Invoke-Chocolatey"
    }
}
