GO ?= go
EXE := $(if $(filter windows,$(shell $(GO) env GOOS)),.exe,)

.PHONY: build test
build:
	mkdir -p build
	CGO_ENABLED=0 $(GO) build -trimpath -o build/shinphony-hook$(EXE) .

test:
	$(GO) test -race -timeout 120s ./...
