# Check for Administrator privileges
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "Elevation required. This script will self elevate to run as an Administrator and continue."
    Start-Sleep 1
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

# Define logs folder and create if it does not exist
$logsFolder = "$ENV:LOCALAPPDATA\debloat-logs\"
If (-Not (Test-Path $logsFolder)) {
    New-Item -Path "$logsFolder" -ItemType Directory
}
$logfile = Get-Date -Format "ddMMyyhhss"
$logfilepath =  "$logsFolder/log-$logfile.log"
Start-Transcript -path $logfilepath -IncludeInvocationHeader -Append

# List of apps to remove
$RemoveAppList = @(
    "Microsoft.BingNews",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Messaging",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.NetworkSpeedTest",
    "Microsoft.News",
    "Microsoft.Office.Lens",
    "Microsoft.Office.OneNote",
    "Microsoft.Office.Sway",
    "Microsoft.OneConnect",
    "Microsoft.People",
    "Microsoft.Print3D",
    "Microsoft.SkypeApp",
    "Microsoft.StorePurchaseApp",
    "Microsoft.Office.Todo.List",
    "Microsoft.Whiteboard",
    "Microsoft.WindowsAlarms",
    "Microsoft.MicrosoftStickyNotes",
    "MicrosoftCorporationII.QuickAssist",
    "microsoft.windowscommunicationsapps",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.Xbox.TCUI",
    # "Microsoft.XboxApp",
    "Microsoft.GamingApp",
    # "Microsoft.GamingServices",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.XboxDevices",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Clipchamp.Clipchamp_yxz26nhyzhsrt",
    "Clipchamp.Clipchamp",
    "Microsoft.YourPhone",
    "Microsoft.MSPaint",
    "Microsoft.MixedReality.Portal",
    "Microsoft.Todos",
    "Microsoft.PowerAutomateDesktop",
    "Microsoft.MicrosoftJournal",
    "Microsoft.BingTranslator",
    "Microsoft.BingWeather",
    "5A894077.McAfeeSecurity",
    "B9ECED6F.ScreenPadMaster",
    "B9ECED6F.ASUSPCAssistant",
    "AdobeSystemsIncorporated.AdobePhotoshopExpress",
    "7EE7776C.LinkedInforWindows",
    "9426MICRO-STARINTERNATION.BusinessCenter",
    "NortonSecurity_1.0.0.1_neutral__cjtsyd8xszapp"
)

# List of apps to install
$InstallAppList = @(
    @{Id="Mozilla.Firefox"; Name="Firefox"; Scope="machine"},
    @{Id="7zip.7zip"; Name="7Zip"; Scope="machine"},
    @{Id="VideoLAN.VLC"; Name="VLC Media Player"; Scope="machine"},
    @{Id="Microsoft.VisualStudioCode"; Name="Visual Studio Code"; Scope="machine"},
    @{Id="Microsoft.PowerToys"; Name="PowerToys"; Scope="user"},
    @{Id="WinDirStat.WinDirStat"; Name="WinDirStat"; Scope="user"},
    @{Id="Git.Git"; Name="Git"; Scope="machine"},
    @{Id="GitHub.cli"; Name="Github CLI"; Scope="user"},
    @{Id="OpenJS.NodeJS.LTS"; Name="NodeJS LTS"; Scope="machine"},
    @{Id="Python.Python.3.11"; Name="Python 3.11"; Scope="machine"},
    @{Id="Postman.Postman"; Name="Postman"; Scope="user"},
    @{Id="Docker.DockerDesktop"; Name="Docker Desktop"; Scope="machine"}
)

# Function to remove unwanted apps
Function Remove-UnwantedApps {
    foreach ($RemoveApp in $RemoveAppList) {
        Get-AppxPackage -Name $RemoveApp | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $RemoveApp | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }
}

# Function to disable Cortana
Function Disable-Cortana {
    Write-Host "Disabling Cortana" -ForegroundColor Red 
    $Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
    $Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
    $Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
    If (!(Test-Path $Cortana1)) {
        New-Item $Cortana1
    }
    Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 
    If (!(Test-Path $Cortana2)) {
        New-Item $Cortana2
    }
    Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 
    Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 
    If (!(Test-Path $Cortana3)) {
        New-Item $Cortana3
    }
    Set-ItemProperty $Cortana3 HarvestContacts -Value 0
    Write-Host "Done" -ForegroundColor Green
}

# Function to configure privacy settings
Function Configure-PrivacySettings {
    Write-Output "Configuring privacy settings"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    If (!(Test-Path $registryPath)) { 
        New-Item $registryPath
    }
    Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1 
    If (!(Test-Path $registryOEM)) {
        New-Item $registryOEM
    }
    Set-ItemProperty $registryOEM  ContentDeliveryAllowed -Value 0 
    Set-ItemProperty $registryOEM  OemPreInstalledAppsEnabled -Value 0 
    Set-ItemProperty $registryOEM  PreInstalledAppsEnabled -Value 0 
    Set-ItemProperty $registryOEM  PreInstalledAppsEverEnabled -Value 0 
    Set-ItemProperty $registryOEM  SilentInstalledAppsEnabled -Value 0 
    Set-ItemProperty $registryOEM  SystemPaneSuggestionsEnabled -Value 0 
    Write-Output "Privacy settings configured" -ForegroundColor Green
}

# Function to disable telemetry and data collection
Function Disable-Telemetry {
    Write-Output "Disabling telemetry and data collection"
    $DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    $DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"    
    If (Test-Path $DataCollection1) {
        Set-ItemProperty $DataCollection1  AllowTelemetry -Value 0 
    }
    If (Test-Path $DataCollection2) {
        Set-ItemProperty $DataCollection2  AllowTelemetry -Value 0 
    }
    If (Test-Path $DataCollection3) {
        Set-ItemProperty $DataCollection3  AllowTelemetry -Value 0 
    }
    Write-Output "Telemetry and data collection disabled" -ForegroundColor Green
}

# Function to disable unnecessary services
Function Disable-UnnecessaryServices {
    Write-Output "Disabling unnecessary services"
    $services = @(
        "DiagTrack",       # Diagnostics Tracking Service
        "dmwappushservice" # WAP Push Message Routing Service
    )
    foreach ($service in $services) {
        Set-Service -Name $service -StartupType Disabled
        Stop-Service -Name $service -Force
    }
    Write-Output "Unnecessary services disabled" -ForegroundColor Green
}

# Function to remove unused optional features
Function Remove-OptionalFeatures {
    Write-Output "Removing unused optional features"
    $features = @(
        "XPSViewer",
        "WorkFolders-Client",
        "MediaPlayback",
        "FaxServicesClientPackage"
    )
    foreach ($feature in $features) {
        Write-Output "Removing $feature"
        Disable-WindowsOptionalFeature -FeatureName $feature -Online -NoRestart
    }
    Write-Output "Optional features removed" -ForegroundColor Green
}

# Function to adjust visual effects for best performance
Function Adjust-VisualEffects {
    Write-Output "Adjusting visual effects for best performance"
    $visualEffects = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    )
    foreach ($key in $visualEffects) {
        If (Test-Path $key) {
            Set-ItemProperty $key VisualFXSetting -Value 2
        }
    }
    Write-Output "Visual effects adjusted" -ForegroundColor Green
}

# Function to clean up disk space
Function Clean-DiskSpace {
    Write-Output "Cleaning up disk space"
    $cleanmgr = "cleanmgr /sagerun:1"
    # Configure CleanMgr settings
    $cleanmgrSettings = @"
[.ShellClassInfo]
[.Default]
File=%windir%\system32\cleanmgr.exe
Settings=40050000
VolumeCache\Internet Cache Files=TRUE
VolumeCache\Temporary Files=TRUE
VolumeCache\Temporary Setup Files=TRUE
VolumeCache\Downloaded Program Files=TRUE
VolumeCache\Temporary Internet Files=TRUE
VolumeCache\System error memory dump files=TRUE
VolumeCache\System error minidump files=TRUE
VolumeCache\Windows Update Cleanup=TRUE
VolumeCache\Windows upgrade log files=TRUE
VolumeCache\Temporary Windows Installation files=TRUE
VolumeCache\Previous Windows Installation=TRUE
VolumeCache\Downloaded Program Files=TRUE
VolumeCache\Recycle Bin=TRUE
VolumeCache\RetailDemo Offline Content=TRUE
VolumeCache\Update Cleanup=TRUE
VolumeCache\Windows Update Cleanup=TRUE
"@

    $cleanmgrSettingsPath = "$env:TEMP\cleanmgr_settings.ini"
    $cleanmgrSettings | Out-File $cleanmgrSettingsPath -Encoding Ascii
    Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/SAGESET:1 /TUNEUP:1 /D $cleanmgrSettingsPath" -Wait
    Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/SAGERUN:1" -Wait
    Write-Output "Disk space cleaned up" -ForegroundColor Green
}

# Function to disable hibernation
Function Disable-Hibernation {
    Write-Output "Disabling hibernation"
    powercfg -h off
    Write-Output "Hibernation disabled" -ForegroundColor Green
}

# Function to adjust power settings for performance
Function Adjust-PowerSettings {
    Write-Output "Adjusting power settings for performance"
    powercfg -duplicatescheme SCHEME_MIN
    Write-Output "Power settings adjusted for performance" -ForegroundColor Green
}

# Function to disable Windows tips and notifications
Function Disable-WindowsTips {
    Write-Output "Disabling Windows tips and notifications"
    $tipsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    If (!(Test-Path $tipsPath)) {
        New-Item -Path $tipsPath -Force
    }
    Set-ItemProperty -Path $tipsPath -Name SubscribedContent-310093Enabled -Value 0
    Set-ItemProperty -Path $tipsPath -Name SubscribedContent-338393Enabled -Value 0
    Set-ItemProperty -Path $tipsPath -Name SubscribedContent-338389Enabled -Value 0
    Set-ItemProperty -Path $tipsPath -Name SubscribedContent-338388Enabled -Value 0
    Write-Output "Windows tips and notifications disabled" -ForegroundColor Green
}

# Function to check if an app is installed
Function Is-AppInstalled {
    param (
        [string]$appId
    )
    $installed = winget list --id $appId 2>&1 | Select-String -Pattern $appId
    return $installed -ne $null
}

# Function to install new apps
Function Install-Apps {
    $installedApps = @()

    foreach ($app in $InstallAppList) {
        if (Is-AppInstalled -appId $app.Id) {
            Write-Host "$($app.Name) is already installed, skipping." -ForegroundColor Yellow
            $installedApps += "$($app.Name) (Already Installed)"
        } else {
            $installCommand = "winget install --id $($app.Id) --scope $($app.Scope) --accept-source-agreements --accept-package-agreements"
            Write-Host "Installing $($app.Name)..."
            Invoke-Expression $installCommand
            If ($?) {
                Write-Host "$($app.Name) installed successfully." -ForegroundColor Green
                $installedApps += "$($app.Name) (Installed)"
            } Else {
                Write-Host "Failed to install $($app.Name)." -ForegroundColor Red
            }
        }
    }

    # Update all apps at the end
    Write-Host "Updating all installed apps..."
    winget upgrade --all --accept-source-agreements --accept-package-agreements
    Write-Host "All apps have been updated." -ForegroundColor Green

    Write-Host "Installation Summary:"
    $installedApps | ForEach-Object { Write-Host $_ }
}

# Execute functions
Remove-UnwantedApps
Disable-Cortana
Configure-PrivacySettings
Disable-Telemetry
Disable-UnnecessaryServices
Remove-OptionalFeatures
Adjust-VisualEffects
Clean-DiskSpace
Disable-Hibernation
Adjust-PowerSettings
Disable-WindowsTips
# Install-Apps

Write-Output "Debloating and app installation complete. Some changes may require a restart to take effect." -ForegroundColor Green
Stop-Transcript
