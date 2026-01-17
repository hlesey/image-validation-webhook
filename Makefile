IMG = ghcr.io/hlesey/image-validation-webhook
TAG = 1.0

test:
	go vet ./...
	go test ./...

build:
	docker build -t $(IMG):$(TAG) .

push: build
	docker push $(IMG):$(TAG)

build-and-push:
	docker buildx build --platform linux/amd64,linux/arm64 -t $(IMG):$(TAG) -t $(IMG):latest --push .

run:
	docker run --rm -p 8080:8080 $(IMG):$(TAG) --allowed-registries=ghcr.io/

.PHONY: test build push build-and-push run
