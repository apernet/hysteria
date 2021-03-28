$env:GOOS = "windows"
go build -ldflags="-w -s" -o "hy_windows.exe" ./cmd

$env:GOOS = "linux"
go build -ldflags="-w -s" -o "hy_linux" ./cmd
