.PHONY: all build run test lint fmt generate wire swag migrate clean help

BINARY := choosy-backend
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date +%Y%m%d)
IMAGE_TAG := $(VERSION)-$(BUILD_DATE)
LDFLAGS := -ldflags="-s -w -X main.Version=$(VERSION)"

all: generate build

build:
	go build $(LDFLAGS) -o $(BINARY) .

run: build
	./$(BINARY)

test:
	go test -v -race -coverprofile=coverage.out ./...

lint:
	golangci-lint run

fmt:
	go fmt ./...
	goimports -w .

generate: wire swag

wire:
	go install github.com/google/wire/cmd/wire@latest
	wire ./...

swag:
	go install github.com/swaggo/swag/cmd/swag@latest
	swag init --parseDependency --parseInternal

check-generate: generate
	@if [ -n "$$(git status --porcelain docs/ wire_gen.go)" ]; then \
		echo "生成的代码有变更，请先运行 make generate 并提交"; \
		git diff docs/ wire_gen.go; \
		exit 1; \
	fi

migrate:
	go run scripts/migrate.go

clean:
	rm -f $(BINARY) coverage.out
	rm -rf dist/

docker-build:
	docker build -t $(BINARY):$(IMAGE_TAG) -t $(BINARY):latest .

docker-run:
	docker run -p 18000:18000 -v $(PWD)/config.toml:/app/config.toml $(BINARY):$(IMAGE_TAG)

help:
	@echo "可用命令:"
	@echo "  make build      - 编译项目"
	@echo "  make run        - 编译并运行"
	@echo "  make test       - 运行测试"
	@echo "  make lint       - 代码检查"
	@echo "  make fmt        - 格式化代码"
	@echo "  make generate   - 生成 wire 和 swag 代码"
	@echo "  make wire       - 生成 wire 依赖注入代码"
	@echo "  make swag       - 生成 swagger 文档"
	@echo "  make migrate    - 运行数据库迁移"
	@echo "  make clean      - 清理构建产物"
	@echo "  make docker-build - 构建 Docker 镜像 (tag: $(IMAGE_TAG))"
	@echo "  make docker-run   - 运行 Docker 容器"

