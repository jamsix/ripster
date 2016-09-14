#!/bin/bash
export GOPATH=$PWD
env GOOS=linux GOARCH=386 go build -o bin/linux-32/ripster main
env GOOS=linux GOARCH=amd64 go build -o bin/linux-64/ripster main
env GOOS=linux GOARCH=arm go build -o bin/linux-arm/ripster main
env GOOS=darwin GOARCH=amd64 go build -o bin/macos/ripster main
env GOOS=windows GOARCH=386 go build -o bin/win/ripster.exe main
chmod +x bin/linux-32/ripster
chmod +x bin/linux-64/ripster
chmod +x bin/linux-arm/ripster
chmod +x bin/macos/ripster
