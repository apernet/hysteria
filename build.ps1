# Hysteria local build script for Windows (PowerShell)

$platforms = @("windows/amd64", "linux/amd64", "darwin/amd64")
$ldflags = "-s -w"

if (!(Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "Error: go is not installed." -ForegroundColor Red
    exit 1
}

if (Test-Path build) {
    Remove-Item -Recurse -Force build
}
New-Item -ItemType Directory -Force -Path build

Write-Host "Starting build..." -ForegroundColor Green

foreach ($platform in $platforms) {
    $env:GOOS = $platform.Split("/")[0]
    $env:GOARCH = $platform.Split("/")[1]
    Write-Host "Building $env:GOOS/$env:GOARCH" -ForegroundColor Green
    $output = "build/hysteria-$env:GOOS-$env:GOARCH"
    if ($env:GOOS -eq "windows") {
        $output = "$output.exe"
    }
    go build -o $output -ldflags $ldflags ./cmd/
}

Write-Host "Build complete." -ForegroundColor Green

Get-ChildItem -Path build | Format-Table -AutoSize
