FROM asecurityteam/serverfull-gateway
COPY gateway-incoming.yaml .
ENV TRANSPORTD_OPENAPI_SPECIFICATION_FILE="gateway-incoming.yaml"
