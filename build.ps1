# Hysteria build script for Windows (PowerShell)

# Environment variable options:
#   - HY_APP_VERSION: App version
#   - HY_APP_COMMIT: App commit hash
#   - HY_APP_PLATFORMS: Platforms to build for (e.g. "windows/amd64,linux/amd64,darwin/amd64")

function PlatformToEnv($os, $arch) {
    $env:CGO_ENABLED = 0
    $env:GOOS = $os
    $env:GOARCH = $arch

    switch -Regex ($arch) {
        "arm" {
            $env:GOARM = "7"
        }
        "armv5" {
            $env:GOARM = "5"
            $env:GOARCH = "arm"
        }
        "armv6" {
            $env:GOARM = "6"
            $env:GOARCH = "arm"
        }
        "armv7" {
            $env:GOARM = "7"
            $env:GOARCH = "arm"
        }
        "mips(le)?" {
            $env:GOMIPS = ""
        }
        "mips-sf" {
            $env:GOMIPS = "softfloat"
            $env:GOARCH = "mips"
        }
        "mipsle-sf" {
            $env:GOMIPS = "softfloat"
            $env:GOARCH = "mipsle"
        }
        "amd64" {
            $env:GOAMD64 = ""
            $env:GOARCH = "amd64"
        }
        "amd64-avx" {
            $env:GOAMD64 = "v3"
            $env:GOARCH = "amd64"
        }
    }
}

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
    $ldflags += " -X 'main.appVersion=$(git describe --tags --always --match "v*")'"
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
    $os = $platform.Split("/")[0]
    $arch = $platform.Split("/")[1]
    PlatformToEnv $os $arch
    Write-Host "Building $os/$arch" -ForegroundColor Green
    $output = "build/hysteria-$os-$arch"
    if ($os -eq "windows") {
        $output = "$output.exe"
    }
    go build -o $output -tags=gpl -ldflags $ldflags -trimpath ./app/cmd/
    if ($LastExitCode -ne 0) {
        Write-Host "Error: failed to build $os/$arch" -ForegroundColor Red
        exit 1
    }
}

Write-Host "Build complete." -ForegroundColor Green

Get-ChildItem -Path build | Format-Table -AutoSize
