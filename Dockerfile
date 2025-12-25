FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY scanner/ ./scanner/
RUN cd scanner && go build -o /app/scanner

FROM alpine:latest
RUN apk add --no-cache bash curl jq coreutils findutils grep

WORKDIR /recon-suite
COPY --from=builder /app/scanner ./scanner/scanner
COPY . .

RUN chmod +x recon-master.sh scanner/scanner && \
    chmod +x modules/*.sh detectors/*.sh utils/*.sh 2>/dev/null || true

ENTRYPOINT ["./recon-master.sh"]
