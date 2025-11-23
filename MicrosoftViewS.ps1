param(
    [string]$a14 = "127.0.0.1",
    [int]$a15 = 8080,
    [int]$a16 = 15,
    [int]$a17 = 60
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$a13 = "----b"

try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.Connect($a14, $a15)
    $networkStream = $tcpClient.GetStream()
    Write-Host "Connected to ${a14}:${a15}. Sending stream..." -ForegroundColor Green
    Write-Host "Press CTRL+C to stop." -ForegroundColor Yellow
} catch {
    Write-Host "Connection error to ${a14}:${a15}: $($_)" -ForegroundColor Red
    return
}

try {
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bitmap = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)

    while ($true) {
        $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.Size)

        $memoryStream = New-Object System.IO.MemoryStream
        $bitmap.Save($memoryStream, [System.Drawing.Imaging.ImageFormat]::Jpeg)
        $jpegBytes = $memoryStream.ToArray()
        $memoryStream.Close()

        $part = "--$a13`r`nContent-Type: image/jpeg`r`nContent-Length: $($jpegBytes.Length)`r`n`r`n"
        $headerBytes = [System.Text.Encoding]::UTF8.GetBytes($part)
        $networkStream.Write($headerBytes, 0, $headerBytes.Length)
        $networkStream.Write($jpegBytes, 0, $jpegBytes.Length)
        $networkStream.Write([System.Text.Encoding]::UTF8.GetBytes("`r`n"), 0, 2)
        $networkStream.Flush()

        [System.Threading.Thread]::Sleep(1000 / $a16)
    }
} catch {
    Write-Host "Error in capture or send: $($_)" -ForegroundColor Red
} finally {
    if ($networkStream) { $networkStream.Close() }
    if ($tcpClient) { $tcpClient.Close() }
}