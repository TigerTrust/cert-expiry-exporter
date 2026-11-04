.PHONY: build test vet install docker helm-lint helm-template clean

BIN=bin/exporter
IMG?=ghcr.io/tigertrust/cert-expiry-exporter:dev

build:
	go build -o $(BIN) ./cmd/exporter

test:
	go test -race ./...

vet:
	go vet ./...

install:
	go install ./cmd/exporter

docker:
	docker build -t $(IMG) .

helm-lint:
	helm lint deploy/chart

helm-template:
	helm template release deploy/chart

clean:
	rm -rf bin
