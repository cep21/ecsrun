build:
	go build ./...

# Run unit tests
test:
	env "GORACE=halt_on_error=1" go test -v -race ./...

# Format the code
fix:
	find . -iname '*.go' -not -path '*/vendor/*' -print0 | xargs -0 gofmt -s -w
	find . -iname '*.go' -not -path '*/vendor/*' -print0 | xargs -0 goimports -w

# Lint the code
lint:
	gometalinter ./...


# ci installs dep by direct version.  Users install with 'go get'
setup_ci:
	curl -L -s https://github.com/golang/dep/releases/download/v$(DEP_VERSION)/dep-linux-amd64 -o $(GOPATH)/bin/dep
	chmod +x $(GOPATH)/bin/dep
	go get -u github.com/alecthomas/gometalinter
	gometalinter --install

# Set back up /vendor folder for benchmarks using dep
redep:
	dep ensure
