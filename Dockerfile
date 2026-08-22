FROM golang:1.23-bookworm AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/ipesign-api ./apps/api/cmd/server

FROM debian:bookworm-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/ipesign-api /usr/local/bin/ipesign-api
COPY apps/web/public ./apps/web/public

ENV PORT=8080
ENV IPESIGN_DATA_DIR=/app/data

EXPOSE 8080

CMD ["ipesign-api"]
