FROM alpine:3.11

LABEL maintainer="mritd <mritd@linux.com>"

ARG VERSION='v0.2.0'

ENV VERSION ${VERSION}
ENV DOWNLOAD_URL https://github.com/tobyxdd/hysteria/releases/download/${VERSION}/hysteria_linux_amd64.tar.gz

RUN set -ex \
    && apk upgrade \
    && apk add bash tzdata ca-certificates tar wget \
    && wget -q ${DOWNLOAD_URL} \
    && tar -zxvf hysteria_linux_amd64.tar.gz \
    && mv hysteria_linux_amd64/cmd /usr/local/bin/hysteria \
    && apk del tar wget \
    && rm -rf hysteria_linux_amd64 /var/cache/apk/*

ENTRYPOINT ["hysteria"]
