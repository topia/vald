#
# Copyright (C) 2019-2020 Vdaas.org Vald team ( kpango, rinx, kmrmt )
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
.PHONY: k8s/manifest/clean
## clean k8s manifests
k8s/manifest/clean:
	rm -rf \
	    k8s/agent \
	    k8s/discoverer \
	    k8s/gateway/vald \
	    k8s/manager/backup \
	    k8s/manager/compressor \
	    k8s/manager/index \
	    k8s/meta \
	    k8s/jobs

.PHONY: k8s/manifest/update
## update k8s manifests using helm templates
k8s/manifest/update: \
	k8s/manifest/clean
	helm template \
	    --values charts/vald/values-dev.yaml \
	    --output-dir tmp-k8s \
	    charts/vald
	mkdir -p k8s/gateway
	mkdir -p k8s/manager
	mv tmp-k8s/vald/templates/agent k8s/agent
	mv tmp-k8s/vald/templates/discoverer k8s/discoverer
	mv tmp-k8s/vald/templates/gateway/vald k8s/gateway/vald
	mv tmp-k8s/vald/templates/manager/backup k8s/manager/backup
	mv tmp-k8s/vald/templates/manager/compressor k8s/manager/compressor
	mv tmp-k8s/vald/templates/manager/index k8s/manager/index
	mv tmp-k8s/vald/templates/meta k8s/meta
	mv tmp-k8s/vald/templates/jobs k8s/jobs
	rm -rf tmp-k8s

.PHONY: k8s/manifest/helm-operator/clean
## clean k8s manifests for helm-operator
k8s/manifest/helm-operator/clean:
	rm -rf \
	    k8s/operator/helm

.PHONY: k8s/manifest/helm-operator/update
## update k8s manifests for helm-operatorusing helm templates
k8s/manifest/helm-operator/update: \
	k8s/manifest/helm-operator/clean
	helm template \
	    --set vald.create=true \
	    --output-dir tmp-k8s \
	    charts/vald-helm-operator
	mkdir -p k8s/operator
	mv tmp-k8s/vald-helm-operator/templates k8s/operator/helm
	rm -rf tmp-k8s
	cp -r charts/vald-helm-operator/crds k8s/operator/helm/crds


.PHONY: k8s/vald/deploy
## deploy vald sample cluster to k8s
k8s/vald/deploy: \
	k8s/external/mysql/deploy \
	k8s/external/redis/deploy
	kubectl apply -f k8s/metrics/metrics-server
	kubectl apply -f k8s/manager/backup
	kubectl apply -f k8s/manager/compressor
	kubectl apply -f k8s/manager/index
	kubectl apply -f k8s/agent
	kubectl apply -f k8s/discoverer
	kubectl apply -f k8s/meta
	kubectl apply -f k8s/gateway/vald

.PHONY: k8s/vald/remove
## remove vald sample cluster from k8s
k8s/vald/remove: \
	k8s/external/mysql/remove \
	k8s/external/redis/remove
	-kubectl delete -f k8s/gateway/vald
	-kubectl delete -f k8s/manager/backup
	-kubectl delete -f k8s/manager/compressor
	-kubectl delete -f k8s/manager/index
	-kubectl delete -f k8s/meta
	-kubectl delete -f k8s/discoverer
	-kubectl delete -f k8s/agent
	-kubectl delete -f k8s/metrics/metrics-server

.PHONY: k8s/vald/deploy/cassandra
## deploy vald sample cluster with cassandra to k8s
k8s/vald/deploy/cassandra: \
	k8s/external/cassandra/deploy
	helm template \
	    --values charts/vald/values-cassandra.yaml \
	    --output-dir tmp-k8s \
	    charts/vald
	kubectl apply -f k8s/metrics/metrics-server
	kubectl apply -f tmp-k8s/vald/templates/manager/backup
	kubectl apply -f tmp-k8s/vald/templates/manager/compressor
	kubectl apply -f tmp-k8s/vald/templates/manager/index
	kubectl apply -f tmp-k8s/vald/templates/agent
	kubectl apply -f tmp-k8s/vald/templates/discoverer
	kubectl apply -f tmp-k8s/vald/templates/meta
	kubectl apply -f tmp-k8s/vald/templates/gateway/vald
	rm -rf tmp-k8s

.PHONY: k8s/vald/deploy/scylla
## deploy vald sample cluster with scylla to k8s
k8s/vald/deploy/scylla: \
	k8s/external/scylla/deploy
	helm template \
	    --values charts/vald/values-scylla.yaml \
	    --output-dir tmp-k8s \
	    charts/vald
	kubectl apply -f k8s/metrics/metrics-server
	kubectl apply -f tmp-k8s/vald/templates/manager/backup
	kubectl apply -f tmp-k8s/vald/templates/manager/compressor
	kubectl apply -f tmp-k8s/vald/templates/manager/index
	kubectl apply -f tmp-k8s/vald/templates/agent
	kubectl apply -f tmp-k8s/vald/templates/discoverer
	kubectl apply -f tmp-k8s/vald/templates/meta
	kubectl apply -f tmp-k8s/vald/templates/gateway/vald
	rm -rf tmp-k8s

.PHONY: k8s/external/mysql/deploy
## deploy mysql to k8s
k8s/external/mysql/deploy:
	kubectl apply -f k8s/jobs/db/initialize/mysql/configmap.yaml
	kubectl apply -f k8s/external/mysql

.PHONY: k8s/external/mysql/remove
## remove mysql from k8s
k8s/external/mysql/remove:
	-kubectl delete -f k8s/external/mysql
	-kubectl delete configmap mysql-config

.PHONY: k8s/external/mysql/initialize
## initialize mysql on k8s
k8s/external/mysql/initialize:
	-kubectl delete -f k8s/jobs/db/initialize/mysql
	kubectl apply -f k8s/external/mysql/secret.yaml
	kubectl apply -f k8s/jobs/db/initialize/mysql

.PHONY: k8s/external/redis/deploy
## deploy redis to k8s
k8s/external/redis/deploy:
	kubectl apply -f k8s/external/redis

.PHONY: k8s/external/redis/remove
## remove redis from k8s
k8s/external/redis/remove:
	-kubectl delete -f k8s/external/redis

.PHONY: k8s/external/redis/initialize
## initialize redis on k8s
k8s/external/redis/initialize:
	-kubectl delete -f k8s/jobs/db/initialize/redis
	kubectl apply -f k8s/external/redis/secret.yaml
	kubectl apply -f k8s/jobs/db/initialize/redis

.PHONY: k8s/external/cassandra/deploy
## deploy cassandra to k8s
k8s/external/cassandra/deploy:
	kubectl apply -f k8s/jobs/db/initialize/cassandra/configmap.yaml
	kubectl apply -f k8s/external/cassandra

.PHONY: k8s/external/cassandra/remove
## remove cassandra from k8s
k8s/external/cassandra/remove:
	-kubectl delete -f k8s/external/cassandra
	-kubectl delete configmap cassandra-initdb

.PHONY: k8s/external/cassandra/initialize
## initialize cassandra on k8s
k8s/external/cassandra/initialize:
	-kubectl delete -f k8s/jobs/db/initialize/cassandra
	-kubectl delete configmap cassandra-initdb
	kubectl apply -f k8s/jobs/db/initialize/cassandra

.PHONY: k8s/external/scylla/deploy
## deploy scylla to k8s
k8s/external/scylla/deploy:
	kubectl apply -f k8s/jobs/db/initialize/cassandra/configmap.yaml
	kubectl apply -f k8s/external/scylla

.PHONY: k8s/external/scylla/remove
## remove scylla from k8s
k8s/external/scylla/remove:
	-kubectl delete -f k8s/external/scylla
	-kubectl delete configmap cassandra-initdb

.PHONY: k8s/metrics/metrics-server/deploy
## deploy metrics-serrver
k8s/metrics/metrics-server/deploy:
	kubectl apply -f k8s/metrics/metrics-server

.PHONY: k8s/metrics/metrics-server/remove
## remove metrics-serrver
k8s/metrics/metrics-server/remove:
	-kubectl delete -f k8s/metrics/metrics-server

.PHONY: k8s/metrics/prometheus/deploy
## deploy prometheus and grafana
k8s/metrics/prometheus/deploy:
	kubectl apply -f k8s/metrics/prometheus
	kubectl create configmap grafana-dashboards --from-file=k8s/metrics/grafana/dashboards/
	kubectl apply -f k8s/metrics/grafana

.PHONY: k8s/metrics/prometheus/remove
## remove prometheus and grafana
k8s/metrics/prometheus/remove:
	-kubectl delete -f k8s/metrics/prometheus
	-kubectl delete configmap grafana-dashboards
	-kubectl delete -f k8s/metrics/grafana

.PHONY: k8s/metrics/jaeger/deploy
## deploy jaeger
k8s/metrics/jaeger/deploy:
	kubectl apply -f k8s/metrics/jaeger

.PHONY: k8s/metrics/jaeger/remove
## remove jaeger
k8s/metrics/jaeger/remove:
	-kubectl delete -f k8s/metrics/jaeger

.PHONY: k8s/metrics/profefe/deploy
## deploy profefe
k8s/metrics/profefe/deploy:
	kubectl apply -f k8s/metrics/profefe

.PHONY: k8s/metrics/profefe/remove
## remove profefe
k8s/metrics/profefe/remove:
	-kubectl delete -f k8s/metrics/profefe

.PHONY: k8s/linkerd/deploy
## deploy linkerd to k8s
k8s/linkerd/deploy:
	linkerd check --pre
	linkerd install | kubectl apply -f -
	linkerd check
	kubectl annotate namespace \
		default \
		linkerd.io/inject=enabled

.PHONY: k8s/linkerd/remove
## remove linkerd from k8s
k8s/linkerd/remove:
	linkerd install --ignore-cluster | kubectl delete -f -

.PHONY: telepresence/install
## install telepresence
telepresence/install: $(BINDIR)/telepresence

$(BINDIR)/telepresence:
	@if echo $(BINDIR) | grep -v '^/' > /dev/null; then \
	    printf "\x1b[31m%s\x1b[0m\n" "WARNING!! BINDIR must be absolute path"; \
	    exit 1; \
	fi
	mkdir -p $(BINDIR)
	curl -L "https://github.com/telepresenceio/telepresence/archive/$(TELEPRESENCE_VERSION).tar.gz" -o telepresence.tar.gz
	tar xzvf telepresence.tar.gz
	rm -rf telepresence.tar.gz
	env PREFIX=$(BINDIR:%/bin=%) telepresence-$(TELEPRESENCE_VERSION)/install.sh
	rm -rf telepresence-$(TELEPRESENCE_VERSION)

.PHONY: telepresence/swap/agent-ngt
## swap agent-ngt deployment using telepresence
telepresence/swap/agent-ngt:
	@$(call telepresence,vald-agent-ngt,vdaas/vald-agent-ngt)

.PHONY: telepresence/swap/gateway
## swap gateway deployment using telepresence
telepresence/swap/gateway:
	@$(call telepresence,vald-gateway,vdaas/vald-gateway)

.PHONY: telepresence/swap/discoverer
## swap discoverer deployment using telepresence
telepresence/swap/discoverer:
	@$(call telepresence,vald-discoverer,vdaas/vald-discoverer-k8s)

.PHONY: telepresence/swap/meta
## swap meta deployment using telepresence
telepresence/swap/meta:
	@$(call telepresence,vald-meta,vdaas/vald-meta-redis)

.PHONY: telepresence/swap/manager-backup
## swap manager-backup deployment using telepresence
telepresence/swap/manager-backup:
	@$(call telepresence,vald-manager-backup,vdaas/vald-manager-backup-mysql)

.PHONY: telepresence/swap/manager-compressor
## swap manager-compressor deployment using telepresence
telepresence/swap/manager-compressor:
	@$(call telepresence,vald-manager-compressor,vdaas/vald-manager-compressor)

.PHONY: telepresence/swap/manager-index
## swap manager-index deployment using telepresence
telepresence/swap/manager-index:
	@$(call telepresence,vald-manager-index,vdaas/vald-manager-index)
