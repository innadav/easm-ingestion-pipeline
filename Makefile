CLUSTER_NAME := easm-local

.PHONY: up build load deploy render-check status down

up: build load deploy

build:
	docker build -f Dockerfile.services -t easm-services:local .
	docker build -f Dockerfile.spark -t easm-spark:local .

load:
	kind get clusters | grep -q "^$(CLUSTER_NAME)$$" || kind create cluster --name $(CLUSTER_NAME)
	kind load docker-image easm-services:local --name $(CLUSTER_NAME)
	kind load docker-image easm-spark:local --name $(CLUSTER_NAME)

deploy:
	kubectl apply -k k8s/overlays/local
	kubectl rollout status deployment/redpanda -n easm --timeout=120s
	kubectl rollout status deployment/redis -n easm --timeout=60s
	kubectl rollout status deployment/postgres -n easm --timeout=60s

render-check:
	kubectl kustomize k8s/overlays/local > /dev/null
	kubectl kustomize k8s/overlays/prod > /dev/null

status:
	kubectl get pods -n easm

down:
	kind delete cluster --name $(CLUSTER_NAME)
