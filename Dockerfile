FROM golang:1.17 as builder
RUN apt-get update && apt-get -y install upx
ENV GO111MODULE=on CGO_ENABLED=0
WORKDIR /src
COPY . .
RUN find . &&  \
  go build \
  -a \
  -trimpath \
  -ldflags "-s -w -extldflags '-static'" \
  -installsuffix cgo \
  -tags netgo \
  -o /bin/app \
  .
RUN strip /bin/app
RUN upx -q -9 /bin/app

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/app /bin/app
ENTRYPOINT ["/bin/app"]