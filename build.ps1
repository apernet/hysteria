# Hysteria build script for Windows (PowerShell)

# Environment variable options:
#   - HY_APP_VERSION: App version
#   - HY_APP_COMMIT: App commit hash
#   - HY_APP_PLATFORMS: Platforms to build for (e.g. "windows/amd64,linux/amd64,darwin/amd64")

if (!(Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "Error: go is not installed." -ForegroundColor Red
    exit 1
}

if (!(Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "Error: git is not installed." -ForegroundColor Red
    exit 1
}
if (!(git rev-parse --is-inside-work-tree 2>$null)) {
    Write-Host "Error: not in a git repository." -ForegroundColor Red
    exit 1
}

$ldflags = "-s -w -X 'main.appDate=$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")'"
if ($env:HY_APP_VERSION) {
    $ldflags += " -X 'main.appVersion=$($env:HY_APP_VERSION)'"
}
else {
    $ldflags += " -X 'main.appVersion=$(git describe --tags --always)'"
}
if ($env:HY_APP_COMMIT) {
    $ldflags += " -X 'main.appCommit=$($env:HY_APP_COMMIT)'"
}
else {
    $ldflags += " -X 'main.appCommit=$(git rev-parse HEAD)'"
}

if ($env:HY_APP_PLATFORMS) {
    $platforms = $env:HY_APP_PLATFORMS.Split(",")
}
else {
    $goos = go env GOOS
    $goarch = go env GOARCH
    $platforms = @("$goos/$goarch")
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
    go build -o $output -tags=gpl -ldflags $ldflags -trimpath ./cmd/
    if ($LastExitCode -ne 0) {
        Write-Host "Error: failed to build $env:GOOS/$env:GOARCH" -ForegroundColor Red
        exit 1
    }
}

Write-Host "Build complete." -ForegroundColor Green

Get-ChildItem -Path build | Format-Table -AutoSize
