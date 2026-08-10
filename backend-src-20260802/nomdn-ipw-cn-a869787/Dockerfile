FROM docker.m.daocloud.io/library/golang:1.26-alpine AS build

ARG GOPROXY=https://goproxy.cn,direct
ARG GOSUMDB=sum.golang.google.cn
ENV GOPROXY=${GOPROXY}
ENV GOSUMDB=${GOSUMDB}
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN gofmt -w main.go node_api.go webtest/advanced.go
RUN GOMAXPROCS=1 go build -p=1 -tags=nomsgpack -trimpath -ldflags="-s -w" -o /out/ipw-backend .

FROM docker.m.daocloud.io/library/alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /out/ipw-backend /usr/local/bin/ipw-backend
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/ipw-backend"]
