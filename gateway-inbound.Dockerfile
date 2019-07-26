FROM asecurityteam/serverfull-gateway
COPY gateway-inbound.yaml .
ENV TRANSPORTD_OPENAPI_SPECIFICATION_FILE="gateway-inbound.yaml"
