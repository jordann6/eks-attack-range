# EKS Attack Range — deploy / demo / harden / destroy.
#
# Nothing here is left running: every target that creates hourly resources has a
# destroy path, and `make destroy` is verified against platform-guardrails'
# hourly-guard. Run the whole red + blue exercise in one sitting, then destroy.
#
# Prereqs: terraform, aws, kubectl, docker, jq. Export a THROWAWAY Anthropic key
# as ANTHROPIC_API_KEY before `make deploy`; revoke it after `make harden`.

SHELL := /usr/bin/env bash
TF := terraform -chdir=infra
NS := summarizer

.DEFAULT_GOAL := help

.PHONY: help
help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n",$$1,$$2}'

# --- infrastructure ---------------------------------------------------------

.PHONY: deploy
deploy: ## Stand up VPC + vulnerable EKS + the app (scopes the endpoint to your IP)
	@test -n "$$ANTHROPIC_API_KEY" || { echo "set ANTHROPIC_API_KEY to a THROWAWAY key first"; exit 1; }
	$(TF) init
	$(TF) apply -auto-approve \
		-var='cluster_public_access_cidrs=["'"$$(curl -4 -s ifconfig.me)"'/32"]'
	$$($(TF) output -raw configure_kubectl)
	$(MAKE) image
	$(MAKE) app

.PHONY: image
image: ## Build and push the summarizer image to ECR
	$(eval ECR := $(shell $(TF) output -raw ecr_repository_url))
	$(eval REGISTRY := $(word 1,$(subst /, ,$(ECR))))
	aws ecr get-login-password --region $$($(TF) output -raw region) \
		| docker login --username AWS --password-stdin $(REGISTRY)
	docker build --platform linux/amd64 -t $(ECR):lab app
	docker push $(ECR):lab

.PHONY: app
app: ## Deploy the app manifests and create the trophy Secret from the throwaway key
	$(eval ECR := $(shell $(TF) output -raw ecr_repository_url))
	kubectl apply -k app/k8s
	cd app/k8s && kubectl set image deployment/summarizer summarizer=$(ECR):lab -n $(NS)
	kubectl -n $(NS) create secret generic summarizer-key \
		--from-literal=ANTHROPIC_API_KEY="$$ANTHROPIC_API_KEY" \
		--dry-run=client -o yaml | kubectl apply -f -
	kubectl -n $(NS) rollout status deployment/summarizer

# --- the exercise -----------------------------------------------------------

.PHONY: url
url: ## Print the app LoadBalancer URL
	@echo "http://$$(kubectl -n $(NS) get svc summarizer -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')"

.PHONY: demo
demo: ## Run the red-team kill chain end to end
	APP_URL="$$($(MAKE) -s url)" attack/killchain.sh

.PHONY: harden
harden: ## Apply the blue-team overlay (reverses the five cluster-side weaknesses)
	kubectl apply -k defend/hardened
	# apply does not prune, so delete the cluster-admin binding the overlay drops.
	kubectl delete clusterrolebinding summarizer-cluster-admin --ignore-not-found
	kubectl -n $(NS) delete secret summarizer-key --ignore-not-found
	kubectl -n $(NS) rollout restart deployment/summarizer
	@echo "Now revoke the throwaway key in the Anthropic console and confirm the app 401s."

.PHONY: test
test: ## Prove the controls deny: cluster-admin binding gone, pod runs restricted
	@echo "expect: no cluster-admin binding for the app SA"
	@! kubectl get clusterrolebinding summarizer-cluster-admin 2>/dev/null \
		&& echo "  PASS: binding removed" || { echo "  FAIL: binding still present"; exit 1; }
	@echo "expect: SA token not auto-mounted"
	@test "$$(kubectl -n $(NS) get sa summarizer -o jsonpath='{.automountServiceAccountToken}')" = "false" \
		&& echo "  PASS: automount disabled" || { echo "  FAIL"; exit 1; }

# --- teardown ---------------------------------------------------------------

.PHONY: destroy
destroy: ## Tear everything down (removes the LB first so TF can delete the VPC)
	-kubectl delete -k app/k8s --ignore-not-found
	-kubectl -n $(NS) delete secret summarizer-key --ignore-not-found
	$(TF) destroy -auto-approve \
		-var='cluster_public_access_cidrs=["'"$$(curl -4 -s ifconfig.me)"'/32"]'

# --- local gates (platform-guardrails equivalents) --------------------------

.PHONY: check
check: ## Local static checks on the infra
	$(TF) fmt -check
	cd infra && terraform validate
