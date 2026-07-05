FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /dns-deception .

FROM alpine:3.23
RUN apk add --no-cache ca-certificates
COPY --from=builder /dns-deception /dns-deception
USER nobody
EXPOSE 5353 8080
ENTRYPOINT ["/dns-deception"]
