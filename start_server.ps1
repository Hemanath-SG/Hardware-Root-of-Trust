# PowerShell Local static HTTP Server
# Runs a simple HTTP server on localhost:8000 to enable secure context for WebAuthn APIs.

$port = 8000
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$port/")

try {
    $listener.Start()
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "  HARDWARE ROOT OF TRUST DEMO SERVER STARTED              " -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "  URL: http://localhost:$port/                             " -ForegroundColor Yellow
    Write-Host "  Secure Context: ACTIVE (WebAuthn Enabled)               " -ForegroundColor Green
    Write-Host "  Workspace: D:\HROT                                       " -ForegroundColor DarkGray
    Write-Host "  Press Ctrl+C to stop the server.                        " -ForegroundColor Gray
    Write-Host "==========================================================" -ForegroundColor Cyan
} catch {
    Write-Host "Error starting server: $_" -ForegroundColor Red
    Write-Host "Make sure port $port is not already in use." -ForegroundColor Yellow
    Exit 1
}

while ($listener.IsListening) {
    try {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response

        $url = $request.Url.LocalPath
        if ($url -eq "/" -or $url -eq "") { $url = "/index.html" }
        
        $filePath = Join-Path (Get-Location) $url
        
        # Security check to prevent directory traversal
        $fullPath = [System.IO.Path]::GetFullPath($filePath)
        $currentDir = [System.IO.Path]::GetFullPath((Get-Location))
        if (-not $fullPath.StartsWith($currentDir)) {
            $response.StatusCode = 403
            $errBytes = [System.Text.Encoding]::UTF8.GetBytes("403 Forbidden")
            $response.OutputStream.Write($errBytes, 0, $errBytes.Length)
            $response.Close()
            continue
        }

        if (Test-Path $fullPath -PathType Leaf) {
            $bytes = [System.IO.File]::ReadAllBytes($fullPath)
            
            # Set Content-Type based on extension
            $ext = [System.IO.Path]::GetExtension($fullPath).ToLower()
            $contentType = "text/plain"
            if ($ext -eq ".html") { $contentType = "text/html; charset=utf-8" }
            elseif ($ext -eq ".css") { $contentType = "text/css; charset=utf-8" }
            elseif ($ext -eq ".js") { $contentType = "application/javascript; charset=utf-8" }
            elseif ($ext -eq ".png") { $contentType = "image/png" }
            elseif ($ext -eq ".jpg" -or $ext -eq ".jpeg") { $contentType = "image/jpeg" }
            elseif ($ext -eq ".ico") { $contentType = "image/x-icon" }
            elseif ($ext -eq ".svg") { $contentType = "image/svg+xml" }
            elseif ($ext -eq ".json") { $contentType = "application/json; charset=utf-8" }
            
            $response.ContentType = $contentType
            $response.ContentLength64 = $bytes.Length
            $response.OutputStream.Write($bytes, 0, $bytes.Length)
        } else {
            $response.StatusCode = 404
            $errBytes = [System.Text.Encoding]::UTF8.GetBytes("404 Not Found")
            $response.OutputStream.Write($errBytes, 0, $errBytes.Length)
        }
        $response.Close()
    } catch {
        # Catch errors if connection is closed or listener is stopped
        if ($listener.IsListening -eq $false) { break }
    }
}
