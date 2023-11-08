all: clean linux macos

macos: 
	go build -o ./dist/ai-proxy-macos .
	chmod +x ./dist/ai-proxy-macos

linux: 
	GOOS=linux GOARCH=amd64  go build -o ./dist/ai-proxy-linux .
	chmod +x ./dist/ai-proxy-linux

clean:
	rm -rf ./dist/*
