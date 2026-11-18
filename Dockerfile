FROM golang:1.27.4-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /reverse-artex ./cmd/reverse-artex

FROM debian:bookworm-slim
RUN groupadd --gid 10001 artex && useradd --uid 10001 --gid artex --no-create-home artex && mkdir -p /app/data/collector && chown -R artex:artex /app
WORKDIR /app
COPY --from=build /reverse-artex /app/reverse-artex
USER 10001:10001
EXPOSE 9081
ENTRYPOINT ["/app/reverse-artex"]
CMD ["-listen", "0.0.0.0:9081", "-out", "/app/data/collector"]
