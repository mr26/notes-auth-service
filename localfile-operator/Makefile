CLUSTER  ?= localfile-lab
IMAGE    ?= localfile-operator:dev
HOST_DIR ?= /tmp/localfiles

.PHONY: help prereqs cluster kyverno crd policies image deploy up run-local demo watch logs webhooks clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

prereqs: ## install k8s tooling (one time; assumes Docker Desktop is installed + signed in)
	brew install kind kubectl helm
	@docker info >/dev/null 2>&1 && echo "docker daemon: running" || \
		echo "docker daemon NOT running — start Docker Desktop, then re-run 'make up'"

cluster: ## create the kind cluster, mounting your Mac's /tmp/localfiles
	mkdir -p $(HOST_DIR)
	kind create cluster --config kind-config.yaml
	kubectl cluster-info --context kind-$(CLUSTER)

kyverno: ## install Kyverno (this IS the admission webhook server)
	helm repo add kyverno https://kyverno.github.io/kyverno/ || true
	helm repo update
	helm install kyverno kyverno/kyverno -n kyverno --create-namespace --wait

crd: ## register the LocalFile custom resource type
	kubectl apply -f manifests/crd.yaml

policies: ## apply the mutating (timestamp) + validating (suffix) policies
	# Kyverno needs explicit read access to CUSTOM resources for policy reports
	kubectl apply -f manifests/kyverno-rbac.yaml
	kubectl apply -f policies/

image: ## build the operator image and load it into the kind node
	docker build -t $(IMAGE) operator/
	kind load docker-image $(IMAGE) --name $(CLUSTER)

deploy: crd image ## run the operator in-cluster
	kubectl apply -f manifests/rbac.yaml
	kubectl apply -f manifests/operator.yaml
	kubectl -n localfile-system rollout status deploy/localfile-operator

up: cluster kyverno crd policies deploy ## full setup from nothing

run-local: ## alternative: run the operator on your Mac (fast dev loop, no image build)
	pip install -r operator/requirements.txt
	LOCALFILE_DIR=$(HOST_DIR) kopf run --standalone --all-namespaces operator/handlers.py

demo: ## prove all three layers work
	@echo "\n=== 1. INVALID LocalFile — validating webhook should reject it ==="
	-@kubectl apply -f examples/localfile-bad.yaml
	@echo "\n=== 2. VALID LocalFile ==="
	@kubectl apply -f examples/localfile-good.yaml
	@sleep 3
	@echo "\n=== 3. mutating webhook stamped an admission timestamp ==="
	@kubectl get localfile hello -o jsonpath='{.metadata.annotations}'; echo
	@echo "\n=== 4. operator reported status ==="
	@kubectl get localfile hello
	@echo "\n=== 5. the real file, on your Mac ==="
	@cat "$(HOST_DIR)/$$(kubectl get localfile hello -o jsonpath='{.spec.filename}')"

watch: ## show the reconcile loop: delete the resource, watch the file disappear
	@ls -l $(HOST_DIR)
	kubectl delete -f examples/localfile-good.yaml
	@sleep 2
	@ls -l $(HOST_DIR)

logs: ## tail operator logs
	kubectl -n localfile-system logs -f deploy/localfile-operator

webhooks: ## inspect the webhook configs Kyverno registered for itself
	kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations
	@echo "\n--- the caBundle + endpoint the API server was told to trust ---"
	kubectl get validatingwebhookconfigurations kyverno-resource-validating-webhook-cfg \
		-o jsonpath='{.webhooks[0].clientConfig.service}{"\n"}' 2>/dev/null || true

clean: ## delete the cluster
	kind delete cluster --name $(CLUSTER)
