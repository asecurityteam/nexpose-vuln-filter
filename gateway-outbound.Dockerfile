FROM asecurityteam/serverfull-gateway
COPY gateway-outbound.yaml .
ENV TRANSPORTD_OPENAPI_SPECIFICATION_FILE="gateway-outbound.yaml"
