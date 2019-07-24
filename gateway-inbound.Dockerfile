FROM asecurityteam/serverfull-gateway
COPY api-inbound.yaml .
ENV TRANSPORTD_OPENAPI_SPECIFICATION_FILE="gateway-inbound.yaml"
