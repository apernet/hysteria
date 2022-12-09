# Release tagging script for Windows (PowerShell)

# Usage:
#   ./tag.ps1 <version>

if (!(Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "Error: git is not installed." -ForegroundColor Red
    exit 1
}
if (!(git rev-parse --is-inside-work-tree 2>$null)) {
    Write-Host "Error: not in a git repository." -ForegroundColor Red
    exit 1
}

if ($args.Length -eq 0) {
    Write-Host "Error: no version argument given." -ForegroundColor Red
    exit 1
}
if ($args[0] -notmatch "^[v]?[0-9]+\.[0-9]+\.[0-9]+$") {
    Write-Host "Error: invalid version argument." -ForegroundColor Red
    exit 1
}
if ($args[0] -notmatch "^[v]") {
    $args[0] = "v" + $args[0]
}

$version = $args[0]
$tags = @($version, "app/$version", "core/$version")

foreach ($tag in $tags) {
    Write-Host "Tagging $tag..."
    git tag $tag
}

Write-Host "Done." -ForegroundColor Green
