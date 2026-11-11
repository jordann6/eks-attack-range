# EKS Attack Range — deploy / demo / harden / destroy.
#
# Nothing here is left running: every target that creates hourly resources has a
# destroy path, and `make destroy-plan` + `make verify-gone` confirm it.
# Run the whole red + blue exercise in one sitting, then destroy.
#
# Prereqs: terraform, aws, kubectl, docker, jq, python3. No vendor API key is
# needed: the trophy is a SYNTHETIC canary token minted per run and accepted
# only by the in-cluster lab receiver, so there is nothing real to revoke.

SHELL := /usr/bin/env bash
TF := terraform -chdir=infra
NS := summarizer

.DEFAULT_GOAL := help

.PHONY: help
help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

# --- infrastructure ---------------------------------------------------------

.PHONY: plan
plan: ## Write infra/tfplan (endpoint scoped to your IPv4 /32) and print the apply command
	$(TF) init -input=false
	$(TF) plan -input=false -out=tfplan \
		-var='cluster_public_access_cidrs=["'"$$(curl -4 -s ifconfig.me)"'/32"]'
	@echo; echo "Read the plan, then run:  terraform -chdir=$(CURDIR)/infra apply $(CURDIR)/infra/tfplan"
	@echo "Then:  make deploy"

.PHONY: deploy
deploy: ## After applying the saved plan: point kubectl at the cluster, push images, deploy the app
	$$($(TF) output -raw configure_kubectl)
	@echo "kubectl context: $$(kubectl config current-context)"
	$(MAKE) image
	$(MAKE) app

.PHONY: image
image: ## Build and push the summarizer, receiver and hardened images to ECR
	$(eval ECR := $(shell $(TF) output -raw ecr_repository_url))
	$(eval REGISTRY := $(word 1,$(subst /, ,$(ECR))))
	aws ecr get-login-password --region $$($(TF) output -raw region) \
		| docker login --username AWS --password-stdin $(REGISTRY)
	docker build --platform linux/amd64 -t $(ECR):lab app
	docker build --platform linux/amd64 -t $(ECR):receiver app/receiver
	docker build --platform linux/amd64 -t $(ECR):hardened app/hardened
	docker push $(ECR):lab
	docker push $(ECR):receiver
	docker push $(ECR):hardened

.PHONY: app
app: ## Deploy the baseline app + receiver and mint the synthetic canary trophy
	$(eval ECR := $(shell $(TF) output -raw ecr_repository_url))
	$(eval CANARY_TOKEN := canary-$(shell openssl rand -hex 16))
	kubectl apply -k app/k8s
	kubectl -n $(NS) create secret generic summarizer-key \
		--from-literal=CANARY_TOKEN="$(CANARY_TOKEN)" \
		--dry-run=client -o yaml | kubectl apply -f -
	kubectl -n $(NS) set image deployment/summarizer summarizer=$(ECR):lab
	kubectl -n $(NS) set image deployment/receiver receiver=$(ECR):receiver
	kubectl -n $(NS) rollout status deployment/receiver
	kubectl -n $(NS) rollout status deployment/summarizer

# --- the exercise -----------------------------------------------------------

.PHONY: url
url: ## Print the app LoadBalancer URL
	@echo "http://$$(kubectl -n $(NS) get svc summarizer -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')"

.PHONY: demo
demo: ## Run the kill chain; each stage is judged on its own (baseline or hardened)
	APP_URL="$$($(MAKE) -s url)" python3 attack/demo.py

# --- blue team --------------------------------------------------------------

.PHONY: harden
harden: ## Apply the blue-team fixes: hardened image + overlay, then verify
	$(eval ECR := $(shell $(TF) output -raw ecr_repository_url))
	kubectl apply -k defend/hardened
	kubectl -n $(NS) set image deployment/summarizer summarizer=$(ECR):hardened
	# apply does not prune, so delete the cluster-admin binding the overlay drops
	# and the plaintext trophy Secret. This is the one authoritative procedure.
	kubectl delete clusterrolebinding summarizer-cluster-admin --ignore-not-found
	kubectl -n $(NS) delete secret summarizer-key --ignore-not-found
	kubectl -n $(NS) rollout status deployment/summarizer
	$(MAKE) verify-hardened

.PHONY: verify-hardened
verify-hardened: ## Prove all five controls hold after `make harden`
	@fail=0; \
	echo "1/5 cluster-admin binding removed"; \
	if kubectl get clusterrolebinding summarizer-cluster-admin >/dev/null 2>&1; then echo "  FAIL: binding present"; fail=1; else echo "  PASS"; fi; \
	echo "2/5 SA token not auto-mounted"; \
	if [ "$$(kubectl -n $(NS) get sa summarizer -o jsonpath='{.automountServiceAccountToken}')" = "false" ]; then echo "  PASS"; else echo "  FAIL"; fail=1; fi; \
	echo "3/5 hardened image in use (no trophy env)"; \
	if kubectl -n $(NS) get deploy summarizer -o jsonpath='{.spec.template.spec.containers[0].image}' | grep -q hardened \
		&& [ -z "$$(kubectl -n $(NS) get deploy summarizer -o jsonpath='{.spec.template.spec.containers[0].env}')" ]; then echo "  PASS"; else echo "  FAIL"; fail=1; fi; \
	url="$$($(MAKE) -s url)"; \
	echo "4/5 diagnose endpoint rejects shell metacharacters"; \
	code=$$(curl -s -o /dev/null -w '%{http_code}' "$$url/tools/diagnose?host=127.0.0.1%3Bid"); \
	if [ "$$code" = "400" ]; then echo "  PASS (400)"; else echo "  FAIL (got $$code, want 400)"; fail=1; fi; \
	echo "5/5 summarize endpoint cannot be steered at IMDS"; \
	body=$$(curl -s "$$url/summarize" -H 'content-type: application/json' -d '{"text":"probe"}'); \
	if echo "$$body" | grep -q '169.254.169.254'; then echo "  FAIL: reached IMDS"; fail=1; else echo "  PASS (fixed upstream only)"; fi; \
	echo "trophy Secret deleted (nothing to exfiltrate)"; \
	if kubectl -n $(NS) get secret summarizer-key >/dev/null 2>&1; then echo "  FAIL: secret present"; fail=1; else echo "  PASS"; fi; \
	test $$fail -eq 0 && echo "ALL CONTROLS HOLD" || { echo "HARDENING INCOMPLETE"; exit 1; }

# --- teardown ---------------------------------------------------------------

.PHONY: destroy-plan
destroy-plan: ## Remove the app first (frees the NLB), then write infra/destroy.tfplan and print the destroy command
	-kubectl delete -k app/k8s --ignore-not-found --wait=true
	-kubectl -n $(NS) delete secret summarizer-key --ignore-not-found
	$(TF) plan -destroy -input=false -out=destroy.tfplan \
		-var='cluster_public_access_cidrs=["'"$$(curl -4 -s ifconfig.me)"'/32"]'
	@echo; echo "Read the plan, then run:  terraform -chdir=$(CURDIR)/infra apply $(CURDIR)/infra/destroy.tfplan"
	@echo "Then:  make verify-gone"

.PHONY: verify-gone
verify-gone: ## Confirm nothing hourly survived: no cluster, NAT gateway, load balancer or ECR repo
	@# Not read from terraform output: after a destroy the state has no outputs.
	@r=$${AWS_REGION:-us-east-1}; \
	echo "clusters:   $$(aws eks list-clusters --region $$r --query 'clusters[?@==`attack-range`]' --output text)"; \
	echo "nat gws:    $$(aws ec2 describe-nat-gateways --region $$r --filter Name=tag:Project,Values=eks-attack-range Name=state,Values=available,pending --query 'NatGateways[].NatGatewayId' --output text)"; \
	echo "load bal:   $$(aws elbv2 describe-load-balancers --region $$r --query 'LoadBalancers[?contains(LoadBalancerName, `k8s`)].LoadBalancerArn' --output text 2>/dev/null) $$(aws elb describe-load-balancers --region $$r --query 'LoadBalancerDescriptions[].LoadBalancerName' --output text)"; \
	echo "ecr:        $$(aws ecr describe-repositories --region $$r --query 'repositories[?contains(repositoryName, `attack-range`)].repositoryName' --output text 2>/dev/null)"; \
	echo "(all four empty = nothing left running)"

# --- local gates (platform-guardrails equivalents) --------------------------

.PHONY: test
test: ## Run the Python unit tests (stage classification + matrix)
	cd attack && python3 -m unittest -v test_demo

.PHONY: check
check: ## Local static checks on the infra + unit tests + manifest render
	$(TF) fmt -check
	cd infra && terraform validate
	kubectl kustomize app/k8s >/dev/null
	kubectl kustomize defend/hardened >/dev/null
	$(MAKE) test
