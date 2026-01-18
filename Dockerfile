# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -ldflags="-s -w" -o zwei-backend .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 app

WORKDIR /app

COPY --from=builder /app/zwei-backend .
COPY config.example.toml ./config.toml

# 构建参数：环境标识（prod 表示生产环境，使用内网 OSS）
ARG ENV=""
ENV APP_ENV=${ENV}

USER app

EXPOSE 18000

CMD ["./zwei-backend"]
