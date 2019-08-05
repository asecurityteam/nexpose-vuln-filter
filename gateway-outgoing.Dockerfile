FROM asecurityteam/serverfull-gateway
COPY gateway-outgoing.yaml .
ENV TRANSPORTD_OPENAPI_SPECIFICATION_FILE="gateway-outgoing.yaml"
