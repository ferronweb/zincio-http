# Node driver image: stdlib http2 with h2c prior knowledge.
#
# Node's http2 client speaks h2c natively for http: URLs, so no TLS setup is
# needed. The version is pinned so an upstream release cannot turn into an
# unexplained failure here.

FROM node:22-slim AS driver
COPY --chmod=0755 node-driver.mjs /usr/local/bin/interop-driver
ENTRYPOINT ["node", "/usr/local/bin/interop-driver"]
