FROM asecurityteam/sdcli:v1 AS BUILDER
RUN mkdir -p /go/src/github.com/asecurityteam/nexpose-vuln-filter
WORKDIR /go/src/github.com/asecurityteam/nexpose-vuln-filter
COPY --chown=sdcli:sdcli . .
RUN GOPROXY="https://gocenter.io" sdcli go dep
RUN CGO_ENABLED=0 GOOS=linux go build -a -o /opt/app main.go

##################################

FROM alpine:latest as CERTS
RUN apk --no-cache add tzdata zip ca-certificates
WORKDIR /usr/share/zoneinfo
# -0 means no compression.  Needed because go's
# tz loader doesn't handle compressed data.
RUN zip -r -0 /zoneinfo.zip .

###################################

FROM scratch
COPY --from=BUILDER /opt/app .
# the timezone data:
COPY --from=CERTS /zoneinfo.zip /
# the tls certificates:
COPY --from=CERTS /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENV ZONEINFO /zoneinfo.zip
ENTRYPOINT ["/app"]
