# go-rbac 开发工作流
#
# 常用入口：
#   make check            本地提交前检查（与 CI 一致：fmt/vet/lint/test）
#   make test-integration 集成测试（自动用 docker compose 拉起 MySQL 8）
#   make hooks            安装 git hooks（.pre-commit / .pre-push）

GO ?= go
GOPATH_BIN := $(shell $(GO) env GOPATH)/bin
MYSQL_DSN ?= root:rootpass@tcp(127.0.0.1:3306)/go_rbac_test?parseTime=true&loc=UTC&charset=utf8mb4

.DEFAULT_GOAL := help
.PHONY: help build test test-race test-integration cover lint vuln fmt fmt-check \
        vet mocks hooks compose-up compose-down check ci clean

help: ## 显示帮助
	@awk 'BEGIN {FS = ":.*##"; printf "\n用法: make \033[36m<target>\033[0m\n\n"} /^[a-zA-Z_-]+:.*?##/ {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## 编译全部包
	$(GO) build ./...

test: ## 单元测试
	$(GO) test ./...

test-race: ## 单元测试（含竞态检测）
	$(GO) test -race ./...

test-integration: compose-up ## 集成测试（需要 Docker，自动拉起 MySQL 8）
	RBAC_TEST_MYSQL_DSN='$(MYSQL_DSN)' $(GO) test -race -v ./repository/gormrepo/

cover: ## 单元测试 + 覆盖率汇总
	$(GO) test -coverprofile=coverage.out ./...
	@$(GO) tool cover -func=coverage.out | tail -1

lint: ## golangci-lint（未安装则自动安装到 GOPATH/bin）
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "安装 golangci-lint..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $(GOPATH_BIN); \
	}
	@PATH="$(GOPATH_BIN):$$PATH" golangci-lint run ./...

vuln: ## govulncheck 漏洞检测（未安装则自动安装）
	@command -v govulncheck >/dev/null 2>&1 || { \
		echo "安装 govulncheck..."; \
		$(GO) install golang.org/x/vuln/cmd/govulncheck@latest; \
	}
	@PATH="$(GOPATH_BIN):$$PATH" govulncheck ./...

fmt: ## gofmt 全量格式化
	$(GO) fmt ./...

fmt-check: ## gofmt 检查（不修改文件）
	@out=$$(gofmt -l . 2>/dev/null); if [ -n "$$out" ]; then \
		echo "以下文件需要 gofmt（执行 make fmt）:"; echo "$$out"; exit 1; fi

vet: ## go vet
	$(GO) vet ./...

mocks: ## 重新生成测试替身（mockery v3）
	@command -v mockery >/dev/null 2>&1 || { \
		echo "安装 mockery v3..."; \
		$(GO) install github.com/vektra/mockery/v3@latest; \
	}
	@PATH="$(GOPATH_BIN):$$PATH" mockery

hooks: ## 安装 git hooks（.pre-commit / .pre-push 复制到 .git/hooks/）
	cp .pre-commit .git/hooks/pre-commit
	cp .pre-push .git/hooks/pre-push
	chmod +x .git/hooks/pre-commit .git/hooks/pre-push
	@echo "git hooks 已安装：pre-commit(gofmt/tidy/vet) pre-push(build/lint/vuln/test)"

compose-up: ## 启动本地 MySQL 8（docker compose）并等待就绪
	docker compose up -d
	@until docker exec go-rbac-mysql mysqladmin ping -h127.0.0.1 -prootpass --silent >/dev/null 2>&1; do \
		echo "等待 MySQL 就绪..."; sleep 2; done
	@docker exec go-rbac-mysql mysql -uroot -prootpass -e \
		'CREATE DATABASE IF NOT EXISTS go_rbac_test CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;' >/dev/null 2>&1 \
		|| docker exec go-rbac-mysql-mysql-1 mysql -uroot -prootpass -e \
		'CREATE DATABASE IF NOT EXISTS go_rbac_test CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;' >/dev/null 2>&1

compose-down: ## 停止本地 MySQL
	docker compose down

check: fmt-check vet lint test ## 本地提交前检查（与 CI 一致）

ci: check test-race vuln ## 本地完整 CI 等价流程

clean: ## 清理构建产物
	rm -f coverage.out
