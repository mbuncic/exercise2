# syntax=docker/dockerfile:1

FROM golang:1.17-alpine AS build
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY portscan.go ./
RUN go build -o ./portscan

FROM alpine
RUN apk update && apk add --no-cache \
    libcap \
    nmap
WORKDIR /app
COPY --from=build /app/portscan /app
RUN mkdir /app/data \
    && addgroup -S -g 9999 nonroot \
    && adduser -S -u 9999 -g nonroot nonroot \
    && chown -R nonroot:nonroot ./ \
    && setcap cap_net_raw+ep /usr/bin/nmap
USER nonroot:nonroot
ENTRYPOINT [ "./portscan" ]
