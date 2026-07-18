BINARY  := layerblame
VERSION ?= dev
LDFLAGS := -s -w -X github.com/AndrewKarpaty/layerblame/cmd.Version=$(VERSION)

.PHONY: build test vet lint fmt clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

clean:
	rm -f $(BINARY)
