CLUSTER_NAME := easm-local

.PHONY: up build load deploy status down

up: build load deploy

build:
	docker build -f Dockerfile.services -t easm-services:local .
	docker build -f Dockerfile.spark -t easm-spark:local .

load:
	kind get clusters | grep -q "^$(CLUSTER_NAME)$$" || kind create cluster --name $(CLUSTER_NAME)
	kind load docker-image easm-services:local --name $(CLUSTER_NAME)
	kind load docker-image easm-spark:local --name $(CLUSTER_NAME)

deploy:
	kubectl apply -f k8s/00-namespace.yaml
	kubectl apply -f k8s/01-infra.yaml
	kubectl rollout status deployment/redpanda -n easm --timeout=120s
	kubectl rollout status deployment/redis -n easm --timeout=60s
	kubectl rollout status deployment/postgres -n easm --timeout=60s
	kubectl apply -f k8s/02-apps.yaml

status:
	kubectl get pods -n easm

down:
	kind delete cluster --name $(CLUSTER_NAME)
