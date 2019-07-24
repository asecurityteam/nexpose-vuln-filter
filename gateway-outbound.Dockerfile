FROM asecurityteam/serverfull-gateway
COPY api-outbound.yaml .
ENV TRANSPORTD_OPENAPI_SPECIFICATION_FILE="gateway-outbound.yaml"
