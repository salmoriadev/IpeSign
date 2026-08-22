FROM node:24-bookworm-slim AS web-builder

WORKDIR /app

COPY package.json package-lock.json tailwind.config.cjs ./
COPY scripts ./scripts
COPY apps/web ./apps/web

RUN npm ci --ignore-scripts \
	&& npm run build:web

FROM golang:1.26-bookworm AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/ipesign-api ./apps/api/cmd/server

FROM debian:bookworm-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates \
	&& rm -rf /var/lib/apt/lists/* \
	&& groupadd --system --gid 10001 ipesign \
	&& useradd --system --uid 10001 --gid ipesign --home-dir /app --shell /usr/sbin/nologin ipesign \
	&& mkdir -p /app/data \
	&& chown -R ipesign:ipesign /app

WORKDIR /app

COPY --from=builder --chown=ipesign:ipesign /out/ipesign-api /usr/local/bin/ipesign-api
COPY --from=web-builder --chown=ipesign:ipesign /app/apps/web/public ./apps/web/public

ENV PORT=8080
ENV IPESIGN_DATA_DIR=/app/data

EXPOSE 8080

USER 10001:10001

CMD ["ipesign-api"]
