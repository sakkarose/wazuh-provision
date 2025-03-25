$ossecPath = "C:\Program Files (x86)\ossec-agent"
$sysmonPath = "$ossecPath\sysmon"
$yaraPath = "$ossecPath\active-response\bin\yara"

$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$yaraUrl = "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip"


# Rerun script as administrator if not already running as administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Stop the Wazuh agent service
Stop-Service -Name wazuh

# Download Sysmon
Invoke-WebRequest -Uri $sysmonUrl -OutFile "$PSScriptRoot\Sysmon.zip"

# Extract Sysmon
Expand-Archive -Path "$PSScriptRoot\Sysmon.zip" -DestinationPath "$PSScriptRoot"

# Create Sysmon directory
if (-Not (Test-Path -Path "$sysmonPath")) {
    New-Item -ItemType Directory -Path "$sysmonPath"
}

# Copy Sysmon to the agent
Copy-Item -Path "$PSScriptRoot\Sysmon64.exe" -Destination "$sysmonPath\Sysmon64.exe"

# Copy configuration file
Copy-Item -Path "$PSScriptRoot\sysmonconfig.xml" -Destination "$sysmonPath\sysmonconfig.xml"

# Start Sysmon with configuration
Start-Process -FilePath "$sysmonPath\Sysmon64.exe" -ArgumentList "/accepteula -i $sysmonPath\sysmonconfig.xml" -NoNewWindow -Wait

# Download the latest YARA binary
Invoke-WebRequest -Uri $yaraUrl -OutFile "$PSScriptRoot\yara-v4.5.2-2326-win64.zip"

# Extract the YARA binary
Expand-Archive -Path "$PSScriptRoot\yara-v4.5.2-2326-win64.zip" -DestinationPath $PSScriptRoot

# Create the YARA directory
if (-Not (Test-Path -Path $yaraPath)) {
    New-Item -ItemType Directory -Path $yaraPath
}

# Copy the YARA binary to the new directory
Copy-Item -Path "$PSScriptRoot\yara64.exe" -Destination $yaraPath

# Create the YARA rules directory
if (-Not (Test-Path -Path "$yaraPath\rules")) {
    New-Item -ItemType Directory -Path "$yaraPath\rules"
}

# Copy the YARA rules to the new directory
Copy-Item -Path "$PSScriptRoot\yara_rules.yar" -Destination "$yaraPath\rules\"

# Copy the yara.bat file to the bin directory
Copy-Item -Path "$PSScriptRoot\yara.bat" -Destination "$ossecPath\active-response\bin\"

# Restart the Wazuh agent service
Restart-Service -Name wazuh