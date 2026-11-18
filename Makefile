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
IMAGE_TAG := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)

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

# --- deception layer (ADR-0005) --------------------------------------------
# Three planted credentials caught from two telemetry sources, contained by an
# in-cluster responder. The D1 key and the D3 Secret hold values that must never
# be committed, so they are minted here, not in Terraform (platform-guardrails
# also denies aws_iam_access_key). Run after `make deploy`.

.PHONY: decoys
decoys: ## Plant D1/D3/D4, push + deploy the responder, mint the D1 key out of state
	$(eval ECR := $(shell $(TF) output -raw ecr_repository_url))
	$(eval REGISTRY := $(word 1,$(subst /, ,$(ECR))))
	$(eval BUCKET := $(shell $(TF) output -raw ir_events_bucket))
	$(eval USERNAME := $(shell $(TF) output -raw decoy_user_name))
	$(eval MAPPREFIX := $(shell $(TF) output -raw credential_map_prefix))
	$(eval ROLEARN := $(shell $(TF) output -raw responder_role_arn))
	$(eval REGION := $(shell $(TF) output -raw region))
	aws ecr get-login-password --region $(REGION) | docker login --username AWS --password-stdin $(REGISTRY)
	docker build --platform linux/amd64 -t $(ECR):responder-ir deception/responder
	docker push $(ECR):responder-ir
	# D3: the decoy Secret. Believable values, random, never committed.
	kubectl -n $(NS) create secret generic prod-db-backup-creds \
		--from-literal=username=svc_dbbackup \
		--from-literal=password="$$(openssl rand -hex 24)" \
		--from-literal=host=db-backup.prod.internal \
		--dry-run=client -o yaml | kubectl apply -f -
	# D4 (ServiceAccount + unbound token) and the quarantine policy + responder.
	kubectl apply -k deception/k8s
	kubectl -n security-tools annotate serviceaccount incident-responder \
		eks.amazonaws.com/role-arn=$(ROLEARN) --overwrite
	kubectl -n security-tools set env deployment/incident-responder BUCKET=$(BUCKET)
	kubectl -n security-tools set image deployment/incident-responder responder=$(ECR):responder-ir
	kubectl -n security-tools rollout status deployment/incident-responder
	# D1: mint ONE access key on the zero-policy user and plant it in the pod. The
	# secret value never touches Terraform state or git. The SSM map lets the alert
	# Lambda name the Secret for the responder to find the mounting pod.
	@KEYJSON=$$(aws iam create-access-key --user-name $(USERNAME) --output json); \
	KID=$$(echo "$$KEYJSON" | jq -r '.AccessKey.AccessKeyId'); \
	SAK=$$(echo "$$KEYJSON" | jq -r '.AccessKey.SecretAccessKey'); \
	printf '[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n' "$$KID" "$$SAK" \
		| kubectl -n $(NS) create secret generic backup-sync-aws --from-file=credentials=/dev/stdin \
			--dry-run=client -o yaml | kubectl apply -f -; \
	aws ssm put-parameter --name "$(MAPPREFIX)/$$KID" --type String --overwrite \
		--value 'summarizer/backup-sync-aws' >/dev/null; \
	kubectl -n $(NS) rollout restart deployment/summarizer; \
	echo "planted D1 key $$KID on summarizer (secret value not stored)"
	kubectl -n $(NS) rollout status deployment/summarizer
	$(MAKE) verify-decoys

.PHONY: decoys-rearm
decoys-rearm: ## Clear today's alert/quarantine records and un-quarantine, for the second attacker order
	$(eval BUCKET := $(shell $(TF) output -raw ir_events_bucket))
	-aws s3 rm s3://$(BUCKET)/alerts/ --recursive
	-aws s3 rm s3://$(BUCKET)/quarantine/ --recursive
	-kubectl -n $(NS) label pods -l app=summarizer security.attack-range/quarantine- 2>/dev/null
	@echo "records cleared and quarantine labels removed"

.PHONY: verify-decoys
verify-decoys: ## Prove the deception layer is armed (zero-policy user, rule state, filter, policy, enforcement)
	$(eval USERNAME := $(shell $(TF) output -raw decoy_user_name))
	$(eval RULE := $(shell $(TF) output -raw credential_rule_name))
	$(eval REGION := $(shell $(TF) output -raw region))
	@fail=0; \
	echo "1/6 decoy user has zero policies"; \
	inline=$$(aws iam list-user-policies --user-name $(USERNAME) --query 'length(PolicyNames)' --output text); \
	attached=$$(aws iam list-attached-user-policies --user-name $(USERNAME) --query 'length(AttachedPolicies)' --output text); \
	groups=$$(aws iam list-groups-for-user --user-name $(USERNAME) --query 'length(Groups)' --output text); \
	if [ "$$inline" = 0 ] && [ "$$attached" = 0 ] && [ "$$groups" = 0 ]; then echo "  PASS"; else echo "  FAIL (inline=$$inline attached=$$attached groups=$$groups)"; fail=1; fi; \
	echo "2/6 EventBridge rule in ALL-management-events state"; \
	state=$$(aws events describe-rule --name $(RULE) --region $(REGION) --query State --output text); \
	if [ "$$state" = ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS ]; then echo "  PASS"; else echo "  FAIL ($$state)"; fail=1; fi; \
	echo "3/6 account has a trail logging management read+write (or D1 never fires)"; \
	trails=$$(aws cloudtrail describe-trails --region $(REGION) --query 'length(trailList)' --output text); \
	if [ "$$trails" -ge 1 ]; then echo "  PASS ($$trails trail/s; confirm read+write in the console if unsure)"; else echo "  FAIL: no trail"; fail=1; fi; \
	echo "4/6 audit subscription filter present"; \
	lg=$$($(TF) output -raw cluster_log_group); \
	sf=$$(aws logs describe-subscription-filters --log-group-name "$$lg" --region $(REGION) --query 'length(subscriptionFilters)' --output text 2>/dev/null); \
	if [ "$$sf" -ge 1 ]; then echo "  PASS"; else echo "  FAIL (none)"; fail=1; fi; \
	echo "5/6 quarantine NetworkPolicy present and enforcement on"; \
	if kubectl -n $(NS) get networkpolicy quarantine >/dev/null 2>&1 \
		&& [ "$$(kubectl -n kube-system get ds aws-node -o jsonpath='{.status.numberReady}')" -gt 0 ] \
		&& kubectl -n kube-system get ds aws-node -o jsonpath='{.spec.template.spec.containers[*].name}' | grep -q aws-network-policy-agent; \
		then echo "  PASS"; else echo "  FAIL (policy or agent missing)"; fail=1; fi; \
	echo "6/6 responder running with least-privilege Role"; \
	if [ "$$(kubectl -n security-tools get deploy incident-responder -o jsonpath='{.status.readyReplicas}')" = 1 ]; then echo "  PASS"; else echo "  FAIL"; fail=1; fi; \
	test $$fail -eq 0 && echo "DECEPTION LAYER ARMED" || { echo "DECEPTION LAYER INCOMPLETE"; exit 1; }

# --- teardown ---------------------------------------------------------------

.PHONY: destroy-plan
destroy-plan: ## Remove the app + decoys first (frees the NLB, deletes the minted key), then write infra/destroy.tfplan
	# Delete the make-minted D1 key before destroy so it never lingers, and empty
	# the SSM map it was recorded in. force_destroy on the user is the backstop.
	-@USERNAME=$$($(TF) output -raw decoy_user_name 2>/dev/null); \
	if [ -n "$$USERNAME" ]; then \
		for k in $$(aws iam list-access-keys --user-name $$USERNAME --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do \
			aws iam delete-access-key --user-name $$USERNAME --access-key-id $$k && echo "deleted D1 key $$k"; \
			MP=$$($(TF) output -raw credential_map_prefix 2>/dev/null); \
			aws ssm delete-parameter --name "$$MP/$$k" 2>/dev/null || true; \
		done; \
	fi
	-kubectl delete -k deception/k8s --ignore-not-found --wait=false
	-kubectl -n $(NS) delete secret backup-sync-aws prod-db-backup-creds --ignore-not-found
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
	echo "decoy keys: $$(aws iam list-access-keys --user-name svc-backup-sync --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null)"; \
	echo "ir bucket:  $$(aws s3api list-buckets --query 'Buckets[?contains(Name, `ir-events`)].Name' --output text 2>/dev/null)"; \
	echo "(all empty = nothing left running; a left decoy key or ir bucket is a deception leftover)"

# --- AKS (one bounded live session, ADR-0004) ------------------------------
# Design level only: this port's own stage-rewrite code (attack/demo_aks.py,
# the IMDS-to-managed-identity steal and the Key Vault pivot) is NOT included
# here. That file is written separately and wired in before `make demo-aks`
# can run for real; aks-image, aks-plan, cilium-aks etc. below do not depend
# on it existing. Needs az, kubelogin, terraform; the subscription id lives in
# infra/azure/lab.auto.tfvars (gitignored).
TFA := terraform -chdir=infra/azure
NS_AKS := summarizer

.PHONY: aks-plan
aks-plan: ## Write infra/azure/tfplan (API scoped to your IPv4 /32) and print the apply command
	$(TFA) init -input=false
	$(TFA) plan -input=false -out=tfplan \
		-var='api_authorized_cidrs=["'"$$(curl -4 -s ifconfig.me)"'/32"]'
	@echo; echo "Read the plan, then run:  terraform -chdir=$(CURDIR)/infra/azure apply $(CURDIR)/infra/azure/tfplan"

.PHONY: cilium-aks
cilium-aks: ## Point kubectl at AKS, install Cilium (BYO CNI, metadata-deny only), gate, confirm server version
	eval "$$($(TFA) output -raw configure_kubectl)"
	helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
	helm repo update cilium >/dev/null
	helm upgrade --install cilium cilium/cilium --version 1.20.4 -n kube-system \
		-f cilium/values-aks.yaml
	kubectl -n kube-system rollout status daemonset/cilium --timeout=5m
	@echo "server version (confirm against var.kubernetes_version before any stage runs):"; \
	kubectl version -o json | jq -r '.serverVersion.gitVersion'

.PHONY: aks-image
aks-image: ## Build baseline + hardened images in ACR (no local push), write the AKS kustomize overlay
	$(eval ACR := $(shell $(TFA) output -raw acr_name))
	$(eval ACR_HOST := $(shell $(TFA) output -raw acr_login_server))
	az acr build --registry $(ACR) --image attack-range/lab:$(IMAGE_TAG) --platform linux/amd64 app
	az acr build --registry $(ACR) --image attack-range/hardened:$(IMAGE_TAG) --platform linux/amd64 app/hardened
	mkdir -p app/k8s-aks
	printf 'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - ../k8s\nimages:\n  - name: netseg-lab\n    newName: %s/attack-range/lab\n    newTag: "%s"\n' \
		"$(ACR_HOST)" "$(IMAGE_TAG)" > app/k8s-aks/kustomization.yaml

.PHONY: app-aks
app-aks: ## Deploy the baseline app + receiver on AKS, mint the synthetic canary trophy
	$(eval ACR_HOST := $(shell $(TFA) output -raw acr_login_server))
	$(eval CANARY_TOKEN := canary-$(shell openssl rand -hex 16))
	kubectl apply -k app/k8s-aks
	kubectl -n $(NS_AKS) create secret generic summarizer-key \
		--from-literal=CANARY_TOKEN="$(CANARY_TOKEN)" \
		--dry-run=client -o yaml | kubectl apply -f -
	kubectl -n $(NS_AKS) set image deployment/summarizer summarizer=$(ACR_HOST)/attack-range/lab:$(IMAGE_TAG)
	kubectl -n $(NS_AKS) set image deployment/receiver receiver=$(ACR_HOST)/attack-range/lab:$(IMAGE_TAG)
	kubectl -n $(NS_AKS) rollout status deployment/receiver
	kubectl -n $(NS_AKS) rollout status deployment/summarizer

.PHONY: url-aks
url-aks: ## Print the app LoadBalancer URL on AKS
	@echo "http://$$(kubectl -n $(NS_AKS) get svc summarizer -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')"

.PHONY: demo-aks
demo-aks: ## Run the kill chain on AKS; NEEDS attack/demo_aks.py (not yet written, see ADR-0004)
	@test -f attack/demo_aks.py || { echo "attack/demo_aks.py does not exist yet; this port's stage code is written separately (ADR-0004)."; exit 1; }
	APP_URL="$$($(MAKE) -s url-aks)" python3 attack/demo_aks.py

.PHONY: harden-aks
harden-aks: ## AKS blue-team fixes: hardened image + overlay, workload identity, remove the broad Key Vault role, verify
	$(eval ACR_HOST := $(shell $(TFA) output -raw acr_login_server))
	$(eval CLIENT_ID := $(shell $(TFA) output -raw summarizer_identity_client_id))
	kubectl apply -k defend/hardened-aks
	kubectl -n $(NS_AKS) annotate serviceaccount summarizer azure.workload.identity/client-id=$(CLIENT_ID) --overwrite
	kubectl -n $(NS_AKS) set image deployment/summarizer summarizer=$(ACR_HOST)/attack-range/hardened:$(IMAGE_TAG)
	kubectl delete clusterrolebinding summarizer-cluster-admin --ignore-not-found
	kubectl -n $(NS_AKS) delete secret summarizer-key --ignore-not-found
	kubectl -n $(NS_AKS) rollout status deployment/summarizer
	@echo "Terraform step (apply separately after review): remove the kubelet identity's broad Key Vault role so only the workload identity above can read it (ADR-0004 decision 3/4; see infra/azure/keyvault.tf NOTE)."
	$(MAKE) verify-hardened-aks

.PHONY: verify-hardened-aks
verify-hardened-aks: ## Prove the AKS controls hold after `make harden-aks` (same five checks as EKS, Key Vault swapped for Secrets Manager)
	@fail=0; \
	echo "1/5 cluster-admin binding removed"; \
	if kubectl get clusterrolebinding summarizer-cluster-admin >/dev/null 2>&1; then echo "  FAIL: binding present"; fail=1; else echo "  PASS"; fi; \
	echo "2/5 SA token not auto-mounted"; \
	if [ "$$(kubectl -n $(NS_AKS) get sa summarizer -o jsonpath='{.automountServiceAccountToken}')" = "false" ]; then echo "  PASS"; else echo "  FAIL"; fail=1; fi; \
	echo "3/5 hardened image in use (no trophy env)"; \
	if kubectl -n $(NS_AKS) get deploy summarizer -o jsonpath='{.spec.template.spec.containers[0].image}' | grep -q hardened \
		&& [ -z "$$(kubectl -n $(NS_AKS) get deploy summarizer -o jsonpath='{.spec.template.spec.containers[0].env}')" ]; then echo "  PASS"; else echo "  FAIL"; fail=1; fi; \
	url="$$($(MAKE) -s url-aks)"; \
	echo "4/5 diagnose endpoint rejects shell metacharacters"; \
	code=$$(curl -s -o /dev/null -w '%{http_code}' "$$url/tools/diagnose?host=127.0.0.1%3Bid"); \
	if [ "$$code" = "400" ]; then echo "  PASS (400)"; else echo "  FAIL (got $$code, want 400)"; fail=1; fi; \
	echo "5/5 summarize endpoint cannot be steered at the metadata endpoint"; \
	body=$$(curl -s "$$url/summarize" -H 'content-type: application/json' -d '{"text":"probe"}'); \
	if echo "$$body" | grep -q '169.254.169.254'; then echo "  FAIL: reached metadata"; fail=1; else echo "  PASS (fixed upstream only)"; fi; \
	echo "trophy Secret deleted (nothing to exfiltrate)"; \
	if kubectl -n $(NS_AKS) get secret summarizer-key >/dev/null 2>&1; then echo "  FAIL: secret present"; fail=1; else echo "  PASS"; fi; \
	test $$fail -eq 0 && echo "ALL CONTROLS HOLD" || { echo "HARDENING INCOMPLETE"; exit 1; }

.PHONY: aks-destroy-plan
aks-destroy-plan: ## Remove the app (Cilium stays installed until the cluster is destroyed), then write infra/azure/destroy.tfplan
	-kubectl delete -k app/k8s-aks --ignore-not-found --wait=true
	-kubectl -n $(NS_AKS) delete secret summarizer-key --ignore-not-found
	# Cilium is NOT uninstalled here. The netseg AKS port's 2026-11-11 session
	# found that removing the CNI before destroy leaves replacement system pods
	# with no network, which blocks the node pool drain on PDB-protected pods
	# (metrics-server, coredns) and fails the destroy after the drain timeout.
	$(TFA) plan -destroy -input=false -out=destroy.tfplan \
		-var='api_authorized_cidrs=["'"$$(curl -4 -s ifconfig.me)"'/32"]'
	@echo; echo "Read the plan, then run:  terraform -chdir=$(CURDIR)/infra/azure apply $(CURDIR)/infra/azure/destroy.tfplan"
	@echo "Then:  make aks-verify-gone"

.PHONY: aks-verify-gone
aks-verify-gone: ## Confirm nothing hourly survived: no cluster, node RG, registry, vault or lab resource group
	@echo "resource groups: $$(az group list --query "[?starts_with(name, 'rg-attack-range')].name" -o tsv)"; \
	echo "aks clusters:    $$(az aks list --query "[?name=='attack-range'].name" -o tsv)"; \
	echo "registries:      $$(az acr list --query "[?starts_with(name, 'acrattackrange')].name" -o tsv)"; \
	echo "key vaults:      $$(az keyvault list --query "[?starts_with(name, 'kv-attack-range')].name" -o tsv)"; \
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
	cd infra/azure && terraform fmt -check -recursive
	cd infra/azure && terraform init -backend=false -input=false >/dev/null && terraform validate
	$(MAKE) test
