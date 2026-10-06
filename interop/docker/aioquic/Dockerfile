# aioquic driver image: an independent Python HTTP/3 + QPACK implementation.
#
# aioquic is the cheapest genuinely independent HTTP/3 client available: it is
# pip-installable, needs no C toolchain, and -- unlike curl -- can observe
# response trailers and 103 Early Hints, which is why it carries those
# scenarios. The version is pinned rather than tracked to latest, so an
# upstream release cannot turn into an unexplained failure here.

FROM python:3.13-slim AS driver
RUN pip install --no-cache-dir "aioquic==1.3.0"
COPY --chmod=0755 clients/aioquic-driver.py /usr/local/bin/interop-driver
ENTRYPOINT ["/usr/local/bin/interop-driver"]
