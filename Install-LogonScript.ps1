$ScriptLocURI = "https://raw.githubusercontent.com/Forsbakk/Intune/master/Intune-LogonScript.ps1"

If (!(Test-Path "C:\Windows\Scripts")) {
    New-Item "C:\Windows\Scripts" -ItemType Directory
}

Invoke-WebRequest -Uri $ScriptLocURI -OutFile "C:\Windows\Scripts\Start-ContinuousDelivery.ps1"

$ScheduledTaskName = "Continuous delivery for Intune"
$ScheduledTaskVersion = "0.0.9"
$ScheduledTask = Get-ScheduledTask -TaskName $ScheduledTaskName

if ($ScheduledTask) {
    Unregister-ScheduledTask -TaskPath "\" -TaskName $ScheduledTaskName -Confirm:$false
}

$User = "SYSTEM"
$Action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-Executionpolicy Bypass -File `"C:\Windows\Scripts\Start-ContinuousDelivery.ps1`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable -StartWhenAvailable -DontStopOnIdleEnd
Register-ScheduledTask -Action $Action -Trigger $Trigger -User $User -RunLevel Highest -Settings $Settings -TaskName $ScheduledTaskName -Description $ScheduledTaskVersion
Start-ScheduledTask -TaskName $ScheduledTaskName