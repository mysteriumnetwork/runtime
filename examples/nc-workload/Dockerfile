FROM alpine:3.23

RUN addgroup -S -g 1000 workload \
    && adduser -S -D -H -u 1000 -G workload workload

COPY --chmod=0555 http-echo /usr/local/bin/http-echo
COPY --chmod=0444 response.txt /response.txt
COPY --chmod=0444 mysterium-runtime.json /mysterium-runtime.json

USER 1000:1000
ENTRYPOINT ["/usr/local/bin/http-echo"]
