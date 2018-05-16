##TODO
#1) Add Company branding
#2) Add Microsoft Store apps

#Define which user to use and which group to assign to
$global:User = "jonas@m365edu967452.onmicrosoft.com"
$global:UserGroup = "All Users"
$global:DeviceGroup = "All Devices"

#Function for fetching AuthToken
function Get-AuthToken {
    Param(
        $User  
    )
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    $tenant = $userUpn.Host

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    If ($AadModule -eq $null) {
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    }

    if ($AadModule -eq $null) {
        Write-Host "AAD module not installed" -ForegroundColor Red
        Exit
    }

    if ($AadModule.count -gt 1) {
        $Latest_Version = ($AadModule | Select-Object version | Sort-Object)[-1]
        $aadModule = $AadModule | Where-Object { $_.version -eq $Latest_Version.version }

        if ($AadModule.count -gt 1) {
            $aadModule = $AadModule | Select-Object -Unique
        }
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    }
    else {
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    }

    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

    $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    $resourceAppIdURI = "https://graph.microsoft.com"
    $authority = "https://login.microsoftonline.com/$Tenant"

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result

    if ($authResult.AccessToken) {
        $authHeader = @{
            'Content-Type'  = 'application/json'
            'Authorization' = "Bearer " + $authResult.AccessToken
            'ExpiresOn'     = $authResult.ExpiresOn
        }
        return $authHeader
    }
}

#Function to get group by name
function Get-AADGroupbyName {
    Param(
        [string]$Name
    )
    $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayname eq '$Name'"

    (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value
}

#Function to add application with JSON
Function Add-MDMApplication {
    Param(
        $JSON
    )

    $uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps"
    Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken
}

#Function to assign apps
Function Add-ApplicationAssignment {
    Param(
        $ApplicationId,
        $TargetGroupId,
        $InstallIntent
    )
    
    $JSON = @"
{
    "mobileAppAssignments": [
    {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$TargetGroupId"
        },
        "intent": "$InstallIntent"
    }
    ]
}
"@
    $uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps/$ApplicationId/assign"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
}

#Function to add PowerShell script to Intune
function Add-PowerShellScript {
    Param(
        $Name,
        $Desc,
        $File,
        $runcontext
    )
    
    $encFile = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$File"));
    $FileName = Get-ChildItem -Path $File

    $JSON = @"
{
    "@odata.type": "#microsoft.graph.deviceManagementScript",
    "displayName": "$Name",
    "description": "$Desc",
    "runSchedule": {
    "@odata.type": "microsoft.graph.runSchedule"
},
    "scriptContent": "$encFile",
    "runAsAccount": "$runcontext",
    "enforceSignatureCheck": false,
    "fileName": "$($FileName.Name)"
}
"@

    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
}

#Function to assign powershell-scripts
function Add-PowerShellScriptAssignment {
    Param(
        $ScriptId,
        $TargetId
    )

    $JSON = @"
{
  "deviceManagementScriptGroupAssignments": [
  {
    "@odata.type": "#microsoft.graph.deviceManagementScriptGroupAssignment",
    "id": "$ScriptId",
    "targetGroupId": "$TargetId"
  }
  ]
}    
"@
    
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$ScriptId/assign"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
}

#Function to add Device Configuration
function Add-DeviceConfiguration {
    Param(
        $JSON
    )

    $uri = "https://graph.microsoft.com/Beta/deviceManagement/deviceConfigurations"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
}

#Function to assign Device Configuration
function Add-DeviceConfigurationAssignment {
    Param(
        $DCId,
        $TargetId
    )

    $assID = "$DCId" + "_" + "$TargetId"

    $JSON = @"
{
  "deviceConfigurationGroupAssignments": [
    {
      "@odata.type": "#microsoft.graph.deviceConfigurationGroupAssignment",
      "id": "$assID",
      "targetGroupId": "$TargetId"
    }
  ]
}
"@
    
    $uri = "https://graph.microsoft.com/Beta/deviceManagement/deviceConfigurations/$DCId/assign"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
}


#Function to add O365 
Function Add-O365 {
    Param(
        $Language,
        $AssignGroup
    )
    $JSON = @"
{
  "@odata.type": "#microsoft.graph.officeSuiteApp",
  "autoAcceptEula": true,
  "description": "Office 365 ProPlus - Assigned",
  "developer": "Microsoft",
  "displayName": "Office 365 ProPlus - Assigned",
  "excludedApps": {
    "groove": true,
    "infoPath": true,
    "sharePointDesigner": true
  },
  "informationUrl": "",
  "isFeatured": false,
  "largeIcon": {
    "type": "image/png",
    "value": "iVBORw0KGgoAAAANSUhEUgAAAF0AAAAeCAMAAAEOZNKlAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAJhUExURf////7z7/i9qfF1S/KCW/i+qv3q5P/9/PrQwfOMae1RG+s8AOxGDfBtQPWhhPvUx/759/zg1vWgg+9fLu5WIvKFX/rSxP728/nCr/FyR+tBBvOMaO1UH+1RHOs+AvSScP3u6f/+/v3s5vzg1+xFDO9kNPOOa/i7pvzj2/vWyes9Af76+Pzh2PrTxf/6+f7y7vOGYexHDv3t5+1SHfi8qPOIZPvb0O1NFuxDCe9hMPSVdPnFs/3q4/vaz/STcu5VIe5YJPWcfv718v/9/e1MFfF4T/F4TvF2TP3o4exECvF0SexIEPONavzn3/vZze1QGvF3Te5dK+5cKvrPwPrQwvKAWe1OGPexmexKEveulfezm/BxRfamiuxLE/apj/zf1e5YJfSXd/OHYv3r5feznPakiPze1P7x7f739f3w6+xJEfnEsvWdf/Wfge1LFPe1nu9iMvnDsfBqPOs/BPOIY/WZevJ/V/zl3fnIt/vTxuxHD+xEC+9mN+5ZJv749vBpO/KBWvBwRP/8+/SUc/etlPjArP/7+vOLZ/F7UvWae/708e1OF/aihvSWdvi8p+tABfSZefvVyPWihfSVde9lNvami+9jM/zi2fKEXvBuQvOKZvalifF5UPJ/WPSPbe9eLfrKuvvd0uxBB/7w7Pzj2vrRw/rOv+1PGfi/q/eymu5bKf3n4PnJuPBrPf3t6PWfgvWegOxCCO9nOO9oOfaskvSYePi5pPi2oPnGtO5eLPevlvKDXfrNvv739Pzd0/708O9gL+9lNfJ9VfrLu/OPbPnDsPBrPus+A/nArfarkQAAAGr5HKgAAADLdFJOU/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8AvuakogAAAAlwSFlzAAAOwwAADsMBx2+oZAAAAz5JREFUOE+tVTtu4zAQHQjppmWzwIJbEVCzpTpjbxD3grQHSOXKRXgCAT6EC7UBVAmp3KwBnmvfzNCyZTmxgeTZJsXx43B+HBHRE34ZkXgkerXFTheeiCkRrbB4UXmp4wSWz5raaQEMTM5TZwuiXoaKgV+6FsmkZQcSy0kA71yMTMGHanX+AzMMGLAQCxU1F/ZwjULPugazl82GM0NEKm/U8EqFwEkO3/EAT4grgl0nucwlk9pcpTTJ4VPA4g/Rb3yIRhhp507e9nTQmZ1OS5RO4sS7nIRPEeHXCHdkw9ZEW2yVE5oIS7peD58Avs7CN+PVCmHh21oOqBdjDzIs+FldPJ74TFESUSJEfVzy9U/dhu+AuOT6eBp6gGKyXEx8euO450ZE4CMfstMFT44broWw/itkYErWXRx+fFArt9Ca9os78TFed0LVIUsmIHrwbwaw3BEOnOk94qVpQ6Ka2HjxewJnfyd6jUtGDQLdWlzmYNYLeKbbGOucJsNabCq1Yub0o92rtR+i30V2dapxYVEePXcOjeCKPnYyit7BtKeNlZqHbr+gt7i+AChWA9RsRs03pxTQc67ouWpxyESvjK5Vs3DVSy3IpkxPm5X+wZoBi+MFHWW69/w8FRhc7VBe6HAhMB2b8Q0XqDzTNZtXUMnKMjwKVaCrB/CSUL7WSx/HsdJC86lFGXwnioTeOMPjV+szlFvrZLA5VMVK4y+41l4e1xfx7Z88o4hkilRUH/qKqwNVlgDgpvYCpH3XwAy5eMCRnezIUxffVXoDql2rTHFDO+pjWnTWzAfrYXn6BFECblUpWGrvPZvBipETjS5ydM7tdXpH41ZCEbBNy/+wFZu71QO2t9pgT+iZEf657Q1vpN94PQNDxUHeKR103LV9nPVOtDikcNKO+2naCw7yKBhOe9Hm79pe8C4/CfC2wDjXnqC94kEeBU3WwN7dt/2UScXas7zDl5GpkY+M8WKv2J7fd4Ib2rGTk+jsC2cleEM7jI9veF7B0MBJrsZqfKd/81q9pR2NZfwJK2JzsmIT1Ns8jUH0UusQBpU8d2JzsHiXg1zXGLqxfitUNTDT/nUUeqDBp2HZVr+Ocqi/Ty3Rf4Jn82xxfSNtAAAAAElFTkSuQmCC"
  },
  "localesToInstall": [
    "$Language"
  ],
  "notes": "",
  "officePlatformArchitecture": "x86",
  "owner": "Microsoft",
  "privacyInformationUrl": "",
  "productIds": [
    "o365ProPlusRetail"
  ],
  "publisher": "Microsoft",
  "updateChannel": "firstReleaseCurrent",
  "useSharedComputerActivation": false
}
"@

    $objID = Get-AADGroupbyName -Name $AssignGroup | Select-Object -ExpandProperty id
    $Create_Application = Add-MDMApplication -JSON $JSON
    $ApplicationId = $Create_Application.id
    Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $objID -InstallIntent "required"
}

#Function to add custom Device Configuration
Function Add-CustomDeviceConfiguration {
    Param(
        $JSON,
        $AssignGroup
    )
    $objID = Get-AADGroupbyName -Name $AssignGroup | Select-Object -ExpandProperty id
    $Device_Config = Add-DeviceConfiguration -JSON $JSON
    $DCid = $Device_Config.id
    Add-DeviceConfigurationAssignment -DCId $DCid -TargetId $objID
}

#Checking auth, prompts if not ok
if ($global:authToken) {
    $DateTime = (Get-Date).ToUniversalTime()
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

    if ($TokenExpires -le 0) {
        if ($User -eq $null -or $User -eq "") {
            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
        }
        $global:authToken = Get-AuthToken -User $User
    }
}
else {
    $global:authToken = Get-AuthToken -User $User
}

##Adds Office 365 nb-no and assigns to $UserGroup
Add-O365 -Language "nb-no" -AssignGroup $UserGroup

##Adds CD4Intune - Beta and assigns to $UserGroup
If (!(Test-Path "C:\temp")) {
    New-Item -Path "C:\temp" -ItemType Directory
    $cleanuptemp = $true
}
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Forsbakk/Intune-Application-Installers/master/Continuous%20delivery%20for%20Intune/Install/Install-CDforIntuneBETA.ps1" -OutFile "C:\temp\Install-CDforIntuneBETA.ps1"

$objID = Get-AADGroupbyName -Name $UserGroup | Select-Object -ExpandProperty id
$Create_Script = Add-PowerShellScript -Name "CD4Intune - Beta" -Desc "CD4Intune" -File "C:\temp\Install-CDforIntuneBETA.ps1" -runcontext "system"
$ScriptId = $Create_Script.id
Add-PowerShellScriptAssignment -ScriptId $ScriptId -TargetId $objID

Remove-Item -Path "C:\temp\Install-CDforIntuneBETA.ps1" -Force
If ($cleanuptemp -eq $true) {
    Remove-Item "C:\temp" -Force
}

##Adds Device_OMA-URIs and assigns to $DeviceGroup
$DEVICE_OMA_URI_JSON = @"
{
    "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
    "description": "HK Device OMA-URIs",
    "displayName": "Device_OMA-URIs",
    "omaSettings": [
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "LastError",
            "description": "Added in Windows 10, version 1803. Error value, if any, associated with Automatic Redeployment operation (typically an HRESULT).",
            "omaUri": "./Device/Vendor/MSFT/RemoteWipe/AutomaticRedeployment/LastError",
            "value": "1"
        },
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Status",
            "description": "Added in Windows 10, version 1803. Status value indicating current state of an Automatic Redeployment operation.",
            "omaUri": "./Device/Vendor/MSFT/RemoteWipe/AutomaticRedeployment/Status",
            "value": "1"
        },
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "doAutomaticRedeployment",
            "description": "Added in Windows 10, version 1803. Exec on this node triggers Automatic Redeployment operation. This works like PC Reset, similar to other existing nodes in this RemoteWipe CSP, except that it keeps the device enrolled in Azure AD and MDM, keeps Wi-Fi profiles, and a few other settings like region, language, keyboard.",
            "omaUri": "./Device/Vendor/MSFT/RemoteWipe/AutomaticRedeployment/doAutomaticRedeployment",
            "value": "1"
        }
    ]
}
"@
Add-CustomDeviceConfiguration -JSON $DEVICE_OMA_URI_JSON -AssignGroup $DeviceGroup

##Adds Vendor_OMA-URIs and assigns to $UserGroup
$VENDOR_OMA_URI_JSON = @"
{
    "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
    "description": "HK Vendor OMA-URIs",
    "displayName": "Vendor_OMA-URIs",
    "omaSettings": [
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "Disable manual MDM unenrollment",
            "description": null,
            "omaUri": "./Vendor/MSFT/Policy/Config/Experience/AllowManualMDMUnenrollment",
            "value": 0
        },
        {
            "@odata.type": "#microsoft.graph.omaSettingBoolean",
            "displayName": "EnableSharedPCMode",
            "description": null,
            "omaUri": "./Vendor/MSFT/SharedPC/EnableSharedPCMode",
            "value": true
        },
        {
            "@odata.type": "#microsoft.graph.omaSettingBoolean",
            "displayName": "SetEduPolicies",
            "description": null,
            "omaUri": "./Vendor/MSFT/SharedPC/SetEduPolicies",
            "value": true
        },
        {
            "@odata.type": "#microsoft.graph.omaSettingBoolean",
            "displayName": "SetPowerPolicies",
            "description": null,
            "omaUri": "./Vendor/MSFT/SharedPC/SetPowerPolicies",
            "value": true
        },
        {
            "@odata.type": "#microsoft.graph.omaSettingBoolean",
            "displayName": "SignInOnResume",
            "description": null,
            "omaUri": "./Vendor/MSFT/SharedPC/SignInOnResume",
            "value": true
        },
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "SleepTimeout",
            "description": null,
            "omaUri": "./Vendor/MSFT/SharedPC/SleepTimeout",
            "value": 900
        },
        {
            "@odata.type": "#microsoft.graph.omaSettingBoolean",
            "displayName": "EnableAccountManager",
            "description": null,
            "omaUri": "./Vendor/MSFT/SharedPC/EnableAccountManager",
            "value": true
        },
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "AccountModel",
            "description": null,
            "omaUri": "./Vendor/MSFT/SharedPC/AccountModel",
            "value": 1
        },
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "DeletionPolicy",
            "description": null,
            "omaUri": "./Vendor/MSFT/SharedPC/DeletionPolicy",
            "value": 1
        },
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "DiskLevelDeletion",
            "description": null,
            "omaUri": "./Vendor/MSFT/SharedPC/DiskLevelDeletion",
            "value": 25
        },
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "DiskLevelCaching",
            "description": null,
            "omaUri": "./Vendor/MSFT/SharedPC/DiskLevelCaching",
            "value": 50
        },
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "MaintenanceStartTime",
            "description": "An integer value that specifies the daily start time of maintenance hour. Given in minutes from midnight. The range is 0-1440",
            "omaUri": "./Vendor/MSFT/SharedPC/MaintenanceStartTime",
            "value": 1140
        },
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "ApplicationDefaults-Associactions",
            "description": null,
            "omaUri": "./Vendor/MSFT/Policy/Config/ApplicationDefaults/DefaultAssociationsConfiguration",
            "value": "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4NCjxEZWZhdWx0QXNzb2NpYXRpb25zPg0KICA8QXNzb2NpYXRpb24gSWRlbnRpZmllcj0iLjNncDIiIFByb2dJZD0iV01QMTEuQXNzb2NGaWxlLjNHMiIgQXBwbGljYXRpb25OYW1lPSJXaW5kb3dzIE1lZGlhIFBsYXllciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5hcnciIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5ibXAiIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5jcjIiIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5jcnciIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5kaWIiIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5lcHViIiBQcm9nSWQ9IkFwcFh2ZXBicDN6NjZhY2Ntc2QweDg3N3piYnhqY3RrcHI2dCIgQXBwbGljYXRpb25OYW1lPSJNaWNyb3NvZnQgRWRnZSIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5lcmYiIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5naWYiIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5odG0iIFByb2dJZD0iQ2hyb21lSFRNTCIgQXBwbGljYXRpb25OYW1lPSJHb29nbGUgQ2hyb21lIiAvPg0KICA8QXNzb2NpYXRpb24gSWRlbnRpZmllcj0iLmh0bWwiIFByb2dJZD0iQ2hyb21lSFRNTCIgQXBwbGljYXRpb25OYW1lPSJHb29nbGUgQ2hyb21lIiAvPg0KICA8QXNzb2NpYXRpb24gSWRlbnRpZmllcj0iLmpmaWYiIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5qcGUiIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5qcGVnIiBQcm9nSWQ9IkFwcFg0M2hueHRieXlwczYyamhlOXNxcGR6eG4xNzkwemV0YyIgQXBwbGljYXRpb25OYW1lPSJCaWxkZXIiIC8+DQogIDxBc3NvY2lhdGlvbiBJZGVudGlmaWVyPSIuanBnIiBQcm9nSWQ9IkFwcFg0M2hueHRieXlwczYyamhlOXNxcGR6eG4xNzkwemV0YyIgQXBwbGljYXRpb25OYW1lPSJCaWxkZXIiIC8+DQogIDxBc3NvY2lhdGlvbiBJZGVudGlmaWVyPSIuanhyIiBQcm9nSWQ9IkFwcFg0M2hueHRieXlwczYyamhlOXNxcGR6eG4xNzkwemV0YyIgQXBwbGljYXRpb25OYW1lPSJCaWxkZXIiIC8+DQogIDxBc3NvY2lhdGlvbiBJZGVudGlmaWVyPSIua2RjIiBQcm9nSWQ9IkFwcFg0M2hueHRieXlwczYyamhlOXNxcGR6eG4xNzkwemV0YyIgQXBwbGljYXRpb25OYW1lPSJCaWxkZXIiIC8+DQogIDxBc3NvY2lhdGlvbiBJZGVudGlmaWVyPSIuTVAyIiBQcm9nSWQ9IldNUDExLkFzc29jRmlsZS5NUDMiIEFwcGxpY2F0aW9uTmFtZT0iV2luZG93cyBNZWRpYSBQbGF5ZXIiIC8+DQogIDxBc3NvY2lhdGlvbiBJZGVudGlmaWVyPSIubXJ3IiBQcm9nSWQ9IkFwcFg0M2hueHRieXlwczYyamhlOXNxcGR6eG4xNzkwemV0YyIgQXBwbGljYXRpb25OYW1lPSJCaWxkZXIiIC8+DQogIDxBc3NvY2lhdGlvbiBJZGVudGlmaWVyPSIubmVmIiBQcm9nSWQ9IkFwcFg0M2hueHRieXlwczYyamhlOXNxcGR6eG4xNzkwemV0YyIgQXBwbGljYXRpb25OYW1lPSJCaWxkZXIiIC8+DQogIDxBc3NvY2lhdGlvbiBJZGVudGlmaWVyPSIubnJ3IiBQcm9nSWQ9IkFwcFg0M2hueHRieXlwczYyamhlOXNxcGR6eG4xNzkwemV0YyIgQXBwbGljYXRpb25OYW1lPSJCaWxkZXIiIC8+DQogIDxBc3NvY2lhdGlvbiBJZGVudGlmaWVyPSIub3JmIiBQcm9nSWQ9IkFwcFg0M2hueHRieXlwczYyamhlOXNxcGR6eG4xNzkwemV0YyIgQXBwbGljYXRpb25OYW1lPSJCaWxkZXIiIC8+DQogIDxBc3NvY2lhdGlvbiBJZGVudGlmaWVyPSIub3hwcyIgUHJvZ0lkPSJXaW5kb3dzLlhQU1JlYWNoVmlld2VyIiBBcHBsaWNhdGlvbk5hbWU9IlhQUy12aXNuaW5nc3Byb2dyYW0iIC8+DQogIDxBc3NvY2lhdGlvbiBJZGVudGlmaWVyPSIucGRmIiBQcm9nSWQ9IkFwcFhkNG5yejhmZjY4c3JuaGY5dDVhOHNianlhcjFjcjcyMyIgQXBwbGljYXRpb25OYW1lPSJNaWNyb3NvZnQgRWRnZSIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5wZWYiIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5wbmciIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5yYWYiIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5yYXciIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5ydzIiIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5yd2wiIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5zcjIiIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii5zcnciIFByb2dJZD0iQXBwWDQzaG54dGJ5eXBzNjJqaGU5c3FwZHp4bjE3OTB6ZXRjIiBBcHBsaWNhdGlvbk5hbWU9IkJpbGRlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii50aWYiIFByb2dJZD0iUGhvdG9WaWV3ZXIuRmlsZUFzc29jLlRpZmYiIEFwcGxpY2F0aW9uTmFtZT0iV2luZG93cyBGb3RvdmlzbmluZyIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii50aWZmIiBQcm9nSWQ9IlBob3RvVmlld2VyLkZpbGVBc3NvYy5UaWZmIiBBcHBsaWNhdGlvbk5hbWU9IldpbmRvd3MgRm90b3Zpc25pbmciIC8+DQogIDxBc3NvY2lhdGlvbiBJZGVudGlmaWVyPSIudHh0IiBQcm9nSWQ9InR4dGZpbGUiIEFwcGxpY2F0aW9uTmFtZT0iTm90aXNibG9rayIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii51cmwiIFByb2dJZD0iSUUuQXNzb2NGaWxlLlVSTCIgQXBwbGljYXRpb25OYW1lPSJJbnRlcm5ldHQtbGVzZXIiIC8+DQogIDxBc3NvY2lhdGlvbiBJZGVudGlmaWVyPSIud2RwIiBQcm9nSWQ9IkFwcFg0M2hueHRieXlwczYyamhlOXNxcGR6eG4xNzkwemV0YyIgQXBwbGljYXRpb25OYW1lPSJCaWxkZXIiIC8+DQogIDxBc3NvY2lhdGlvbiBJZGVudGlmaWVyPSIud2Vic2l0ZSIgUHJvZ0lkPSJJRS5Bc3NvY0ZpbGUuV0VCU0lURSIgQXBwbGljYXRpb25OYW1lPSJJbnRlcm5ldCBFeHBsb3JlciIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Ii54cHMiIFByb2dJZD0iV2luZG93cy5YUFNSZWFjaFZpZXdlciIgQXBwbGljYXRpb25OYW1lPSJYUFMtdmlzbmluZ3Nwcm9ncmFtIiAvPg0KICA8QXNzb2NpYXRpb24gSWRlbnRpZmllcj0iYmluZ21hcHMiIFByb2dJZD0iQXBwWHA5Z2t3Y2N2azZmYTZ5eWZxM3Rtc2s4d3MybnByazFwIiBBcHBsaWNhdGlvbk5hbWU9IkthcnQiIC8+DQogIDxBc3NvY2lhdGlvbiBJZGVudGlmaWVyPSJodHRwIiBQcm9nSWQ9IkNocm9tZUhUTUwiIEFwcGxpY2F0aW9uTmFtZT0iR29vZ2xlIENocm9tZSIgLz4NCiAgPEFzc29jaWF0aW9uIElkZW50aWZpZXI9Imh0dHBzIiBQcm9nSWQ9IkNocm9tZUhUTUwiIEFwcGxpY2F0aW9uTmFtZT0iR29vZ2xlIENocm9tZSIgLz4NCjwvRGVmYXVsdEFzc29jaWF0aW9ucz4="
        }
    ]
}
"@
Add-CustomDeviceConfiguration -JSON $VENDOR_OMA_URI_JSON -AssignGroup $UserGroup

##Adds custom Device Configuration and assigns to $Group
$Device_Restriction_JSON = @"
{
    "@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
    "description": "Win10 - Device Configuration",
    "displayName": "Win10 - Device Configuration",
    "enableAutomaticRedeployment": true,
    "assignedAccessSingleModeUserName": null,
    "assignedAccessSingleModeAppUserModelId": null,
    "microsoftAccountSignInAssistantSettings": "notConfigured",
    "authenticationAllowSecondaryDevice": false,
    "authenticationAllowFIDODevice": false,
    "cryptographyAllowFipsAlgorithmPolicy": false,
    "displayAppListWithGdiDPIScalingTurnedOn": [],
    "displayAppListWithGdiDPIScalingTurnedOff": [],
    "enterpriseCloudPrintDiscoveryEndPoint": null,
    "enterpriseCloudPrintOAuthAuthority": null,
    "enterpriseCloudPrintOAuthClientIdentifier": null,
    "enterpriseCloudPrintResourceIdentifier": null,
    "enterpriseCloudPrintDiscoveryMaxLimit": null,
    "enterpriseCloudPrintMopriaDiscoveryResourceIdentifier": null,
    "messagingBlockSync": false,
    "messagingBlockMMS": false,
    "messagingBlockRichCommunicationServices": false,
    "searchBlockDiacritics": false,
    "searchDisableAutoLanguageDetection": false,
    "searchDisableIndexingEncryptedItems": false,
    "searchEnableRemoteQueries": false,
    "searchDisableUseLocation": false,
    "searchDisableIndexerBackoff": false,
    "searchDisableIndexingRemovableDrive": false,
    "searchEnableAutomaticIndexSizeManangement": false,
    "securityBlockAzureADJoinedDevicesAutoEncryption": false,
    "diagnosticsDataSubmissionMode": "userDefined",
    "oneDriveDisableFileSync": false,
    "systemTelemetryProxyServer": null,
    "inkWorkspaceAccess": "notConfigured",
    "inkWorkspaceBlockSuggestedApps": false,
    "smartScreenEnableAppInstallControl": false,
    "personalizationDesktopImageUrl": null,
    "personalizationLockScreenImageUrl": "http://sublog.org/storage/DefaultLockScreen_hrt.jpg",
    "bluetoothAllowedServices": [],
    "bluetoothBlockAdvertising": false,
    "bluetoothBlockDiscoverableMode": false,
    "bluetoothBlockPrePairing": false,
    "edgeBlockAutofill": false,
    "edgeBlocked": false,
    "edgeCookiePolicy": "userDefined",
    "edgeBlockDeveloperTools": false,
    "edgeBlockSendingDoNotTrackHeader": false,
    "edgeBlockExtensions": false,
    "edgeBlockInPrivateBrowsing": false,
    "edgeBlockJavaScript": false,
    "edgeBlockPasswordManager": false,
    "edgeBlockAddressBarDropdown": false,
    "edgeBlockCompatibilityList": false,
    "edgeClearBrowsingDataOnExit": false,
    "edgeAllowStartPagesModification": false,
    "edgeDisableFirstRunPage": false,
    "edgeBlockLiveTileDataCollection": false,
    "edgeSyncFavoritesWithInternetExplorer": false,
    "edgeFavoritesListLocation": null,
    "edgeBlockEditFavorites": false,
    "cellularBlockDataWhenRoaming": false,
    "cellularBlockVpn": false,
    "cellularBlockVpnWhenRoaming": false,
    "cellularData": "allowed",
    "defenderBlockEndUserAccess": false,
    "defenderDaysBeforeDeletingQuarantinedMalware": null,
    "defenderDetectedMalwareActions": null,
    "defenderSystemScanSchedule": "userDefined",
    "defenderFilesAndFoldersToExclude": [],
    "defenderFileExtensionsToExclude": [],
    "defenderScanMaxCpu": null,
    "defenderMonitorFileActivity": "userDefined",
    "defenderPotentiallyUnwantedAppAction": null,
    "defenderProcessesToExclude": [],
    "defenderPromptForSampleSubmission": "userDefined",
    "defenderRequireBehaviorMonitoring": false,
    "defenderRequireCloudProtection": false,
    "defenderRequireNetworkInspectionSystem": false,
    "defenderRequireRealTimeMonitoring": false,
    "defenderScanArchiveFiles": false,
    "defenderScanDownloads": false,
    "defenderScanNetworkFiles": false,
    "defenderScanIncomingMail": false,
    "defenderScanMappedNetworkDrivesDuringFullScan": false,
    "defenderScanRemovableDrivesDuringFullScan": false,
    "defenderScanScriptsLoadedInInternetExplorer": false,
    "defenderSignatureUpdateIntervalInHours": null,
    "defenderScanType": "userDefined",
    "defenderScheduledScanTime": null,
    "defenderScheduledQuickScanTime": null,
    "defenderCloudBlockLevel": "notConfigured",
    "defenderCloudExtendedTimeout": null,
    "lockScreenAllowTimeoutConfiguration": false,
    "lockScreenBlockActionCenterNotifications": false,
    "lockScreenBlockCortana": false,
    "lockScreenBlockToastNotifications": false,
    "lockScreenTimeoutInSeconds": null,
    "passwordBlockSimple": false,
    "passwordExpirationDays": null,
    "passwordMinimumLength": null,
    "passwordMinutesOfInactivityBeforeScreenTimeout": null,
    "passwordMinimumCharacterSetCount": null,
    "passwordPreviousPasswordBlockCount": null,
    "passwordRequired": false,
    "passwordRequireWhenResumeFromIdleState": false,
    "passwordRequiredType": "deviceDefault",
    "passwordSignInFailureCountBeforeFactoryReset": null,
    "privacyAdvertisingId": "notConfigured",
    "privacyAutoAcceptPairingAndConsentPrompts": false,
    "privacyBlockInputPersonalization": false,
    "privacyBlockPublishUserActivities": false,
    "privacyBlockActivityFeed": false,
    "startBlockUnpinningAppsFromTaskbar": true,
    "startMenuAppListVisibility": "userDefined",
    "startMenuHideChangeAccountSettings": false,
    "startMenuHideFrequentlyUsedApps": true,
    "startMenuHideHibernate": true,
    "startMenuHideLock": false,
    "startMenuHidePowerButton": false,
    "startMenuHideRecentJumpLists": false,
    "startMenuHideRecentlyAddedApps": true,
    "startMenuHideRestartOptions": false,
    "startMenuHideShutDown": true,
    "startMenuHideSignOut": false,
    "startMenuHideSleep": false,
    "startMenuHideSwitchAccount": false,
    "startMenuHideUserTile": false,
    "startMenuLayoutEdgeAssetsXml": null,
    "startMenuLayoutXml": "PExheW91dE1vZGlmaWNhdGlvblRlbXBsYXRlDQogICAgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vU3RhcnQvMjAxNC9MYXlvdXRNb2RpZmljYXRpb24iDQogICAgeG1sbnM6ZGVmYXVsdGxheW91dD0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9TdGFydC8yMDE0L0Z1bGxEZWZhdWx0TGF5b3V0Ig0KICAgIHhtbG5zOnN0YXJ0PSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL1N0YXJ0LzIwMTQvU3RhcnRMYXlvdXQiDQogICAgeG1sbnM6dGFza2Jhcj0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9TdGFydC8yMDE0L1Rhc2tiYXJMYXlvdXQiDQogICAgVmVyc2lvbj0iMSI+DQogIDxMYXlvdXRPcHRpb25zIFN0YXJ0VGlsZUdyb3VwQ2VsbFdpZHRoPSI2IiAvPg0KICA8RGVmYXVsdExheW91dE92ZXJyaWRlPg0KICAgIDxTdGFydExheW91dENvbGxlY3Rpb24+DQogICAgICA8ZGVmYXVsdGxheW91dDpTdGFydExheW91dCBHcm91cENlbGxXaWR0aD0iNiI+DQogICAgICAgIDxzdGFydDpHcm91cCBOYW1lPSIiPg0KICAgICAgICAgIDxzdGFydDpUaWxlIFNpemU9IjJ4MiIgQ29sdW1uPSIwIiBSb3c9IjIiIEFwcFVzZXJNb2RlbElEPSJNaWNyb3NvZnQuTVNQYWludF84d2VreWIzZDhiYndlIU1pY3Jvc29mdC5NU1BhaW50IiAvPg0KICAgICAgICAgIDxzdGFydDpUaWxlIFNpemU9IjJ4MiIgQ29sdW1uPSI0IiBSb3c9IjAiIEFwcFVzZXJNb2RlbElEPSJNaWNyb3NvZnQuT2ZmaWNlLk9uZU5vdGVfOHdla3liM2Q4YmJ3ZSFtaWNyb3NvZnQub25lbm90ZWltIiAvPg0KICAgICAgICAgIDxzdGFydDpUaWxlIFNpemU9IjR4MiIgQ29sdW1uPSIwIiBSb3c9IjAiIEFwcFVzZXJNb2RlbElEPSJNaWNyb3NvZnQuV2luZG93cy5QaG90b3NfOHdla3liM2Q4YmJ3ZSFBcHAiIC8+DQogICAgICAgICAgPHN0YXJ0OlRpbGUgU2l6ZT0iMngyIiBDb2x1bW49IjIiIFJvdz0iMiIgQXBwVXNlck1vZGVsSUQ9Ik1pY3Jvc29mdC5NaW5lY3JhZnRFZHVjYXRpb25FZGl0aW9uXzh3ZWt5YjNkOGJid2UhQXBwIiAvPg0KICAgICAgICAgIDxzdGFydDpUaWxlIFNpemU9IjJ4MiIgQ29sdW1uPSI0IiBSb3c9IjIiIEFwcFVzZXJNb2RlbElEPSJMRUdPRWR1Y2F0aW9uLkxFR09NSU5EU1RPUk1TRWR1Y2F0aW9uRVYzUHJvZ3JhbW1pbl9ieTNwMGhzbTJqemZ5IUxFR09FZHVjYXRpb24uTEVHT01JTkRTVE9STVNFZHVjYXRpb25FVjNQcm9ncmFtbWluIiAvPg0KICAgICAgICAgIDxzdGFydDpUaWxlIFNpemU9IjJ4MiIgQ29sdW1uPSIwIiBSb3c9IjQiIEFwcFVzZXJNb2RlbElEPSJWaWRlb0xBTi5WTENfcGF6NnIxcmV3bmgwYSFBcHAiIC8+DQogICAgICAgIDwvc3RhcnQ6R3JvdXA+DQogICAgICA8L2RlZmF1bHRsYXlvdXQ6U3RhcnRMYXlvdXQ+DQogICAgPC9TdGFydExheW91dENvbGxlY3Rpb24+DQogIDwvRGVmYXVsdExheW91dE92ZXJyaWRlPg0KICAgPEN1c3RvbVRhc2tiYXJMYXlvdXRDb2xsZWN0aW9uIFBpbkxpc3RQbGFjZW1lbnQ9IlJlcGxhY2UiPg0KICAgIDxkZWZhdWx0bGF5b3V0OlRhc2tiYXJMYXlvdXQ+DQogICAgICA8dGFza2JhcjpUYXNrYmFyUGluTGlzdD4NCiAgICAgICAgICAgICAgPHRhc2tiYXI6RGVza3RvcEFwcCBEZXNrdG9wQXBwbGljYXRpb25MaW5rUGF0aD0iJUFQUERBVEElXE1pY3Jvc29mdFxXaW5kb3dzXFN0YXJ0IE1lbnVcUHJvZ3JhbXNcU3lzdGVtIFRvb2xzXEZpbGUgRXhwbG9yZXIubG5rIiAvPg0KICAgICAgPC90YXNrYmFyOlRhc2tiYXJQaW5MaXN0Pg0KICAgIDwvZGVmYXVsdGxheW91dDpUYXNrYmFyTGF5b3V0Pg0KICA8L0N1c3RvbVRhc2tiYXJMYXlvdXRDb2xsZWN0aW9uPg0KPC9MYXlvdXRNb2RpZmljYXRpb25UZW1wbGF0ZT4=",
    "startMenuMode": "userDefined",
    "startMenuPinnedFolderDocuments": "notConfigured",
    "startMenuPinnedFolderDownloads": "notConfigured",
    "startMenuPinnedFolderFileExplorer": "notConfigured",
    "startMenuPinnedFolderHomeGroup": "notConfigured",
    "startMenuPinnedFolderMusic": "notConfigured",
    "startMenuPinnedFolderNetwork": "notConfigured",
    "startMenuPinnedFolderPersonalFolder": "notConfigured",
    "startMenuPinnedFolderPictures": "notConfigured",
    "startMenuPinnedFolderSettings": "notConfigured",
    "startMenuPinnedFolderVideos": "notConfigured",
    "settingsBlockSettingsApp": false,
    "settingsBlockSystemPage": false,
    "settingsBlockDevicesPage": false,
    "settingsBlockNetworkInternetPage": false,
    "settingsBlockPersonalizationPage": false,
    "settingsBlockAccountsPage": false,
    "settingsBlockTimeLanguagePage": false,
    "settingsBlockEaseOfAccessPage": false,
    "settingsBlockPrivacyPage": false,
    "settingsBlockUpdateSecurityPage": false,
    "settingsBlockAppsPage": false,
    "settingsBlockGamingPage": false,
    "windowsSpotlightBlockConsumerSpecificFeatures": false,
    "windowsSpotlightBlocked": false,
    "windowsSpotlightBlockOnActionCenter": false,
    "windowsSpotlightBlockTailoredExperiences": false,
    "windowsSpotlightBlockThirdPartyNotifications": false,
    "windowsSpotlightBlockWelcomeExperience": false,
    "windowsSpotlightBlockWindowsTips": false,
    "windowsSpotlightConfigureOnLockScreen": "notConfigured",
    "networkProxyApplySettingsDeviceWide": false,
    "networkProxyDisableAutoDetect": false,
    "networkProxyAutomaticConfigurationUrl": null,
    "networkProxyServer": null,
    "accountsBlockAddingNonMicrosoftAccountEmail": false,
    "antiTheftModeBlocked": false,
    "bluetoothBlocked": false,
    "cameraBlocked": false,
    "connectedDevicesServiceBlocked": false,
    "certificatesBlockManualRootCertificateInstallation": false,
    "copyPasteBlocked": false,
    "cortanaBlocked": false,
    "deviceManagementBlockFactoryResetOnMobile": false,
    "deviceManagementBlockManualUnenroll": false,
    "safeSearchFilter": "userDefined",
    "edgeBlockPopups": false,
    "edgeBlockSearchSuggestions": false,
    "edgeBlockSendingIntranetTrafficToInternetExplorer": false,
    "edgeRequireSmartScreen": false,
    "edgeEnterpriseModeSiteListLocation": null,
    "edgeFirstRunUrl": null,
    "edgeSearchEngine": null,
    "edgeHomepageUrls": [],
    "edgeBlockAccessToAboutFlags": false,
    "smartScreenBlockPromptOverride": false,
    "smartScreenBlockPromptOverrideForFiles": false,
    "webRtcBlockLocalhostIpAddress": false,
    "internetSharingBlocked": false,
    "settingsBlockAddProvisioningPackage": false,
    "settingsBlockRemoveProvisioningPackage": false,
    "settingsBlockChangeSystemTime": false,
    "settingsBlockEditDeviceName": false,
    "settingsBlockChangeRegion": false,
    "settingsBlockChangeLanguage": false,
    "settingsBlockChangePowerSleep": false,
    "locationServicesBlocked": false,
    "microsoftAccountBlocked": false,
    "microsoftAccountBlockSettingsSync": false,
    "nfcBlocked": false,
    "resetProtectionModeBlocked": false,
    "screenCaptureBlocked": false,
    "storageBlockRemovableStorage": false,
    "storageRequireMobileDeviceEncryption": false,
    "usbBlocked": false,
    "voiceRecordingBlocked": false,
    "wiFiBlockAutomaticConnectHotspots": false,
    "wiFiBlocked": false,
    "wiFiBlockManualConfiguration": false,
    "wiFiScanInterval": null,
    "wirelessDisplayBlockProjectionToThisDevice": false,
    "wirelessDisplayBlockUserInputFromReceiver": false,
    "wirelessDisplayRequirePinForPairing": false,
    "windowsStoreBlocked": false,
    "appsAllowTrustedAppsSideloading": "notConfigured",
    "windowsStoreBlockAutoUpdate": false,
    "developerUnlockSetting": "notConfigured",
    "sharedUserAppDataAllowed": false,
    "appsBlockWindowsStoreOriginatedApps": false,
    "windowsStoreEnablePrivateStoreOnly": true,
    "storageRestrictAppDataToSystemVolume": false,
    "storageRestrictAppInstallToSystemVolume": false,
    "gameDvrBlocked": true,
    "experienceBlockDeviceDiscovery": false,
    "experienceBlockErrorDialogWhenNoSIM": false,
    "experienceBlockTaskSwitcher": false,
    "logonBlockFastUserSwitching": false
}
"@
Add-CustomDeviceConfiguration -JSON $Device_Restriction_JSON -AssignGroup $UserGroup