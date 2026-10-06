# hyper-h2 driver image: the popular Python HTTP/2 stack with raw frame control.
#
# Unlike curl this client can observe 103 Early Hints and response trailers
# over HTTP/2, which closes the container-coverage gap curl leaves there. The
# version is pinned rather than tracked to latest, so an upstream release
# cannot turn into an unexplained failure here.

FROM python:3.13-slim AS driver
RUN pip install --no-cache-dir "h2==4.4.1"
COPY --chmod=0755 clients/h2-driver.py /usr/local/bin/interop-driver
ENTRYPOINT ["/usr/local/bin/interop-driver"]
