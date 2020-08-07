FROM golang:1.14.7-alpine3.12 AS builder

LABEL maintainer="mritd <mritd@linux.com>"

# The following parameters are used to set compilation information(such as compilation time,
# commit id, etc.). Use "docker build --build-arg VERSION=1.1.1 ..." to set these parameters.
# These parameters can be set automatically through CI Server.
ARG VERSION="Unknown"
ARG COMMIT="Unknown"
ARG TIMESTAMP="Unknown"

# GOPROXY is disabled by default, use:
# docker build --build-arg GOPROXY="https://goproxy.io" ...
# to enable GOPROXY.
ARG GOPROXY=""

ENV VERSION ${VERSION}
ENV COMMIT ${COMMIT}
ENV TIMESTAMP ${TIMESTAMP}
ENV GOPROXY ${GOPROXY}

# go mod is always enabled
ENV GO111MODULE on

COPY . /go/src/github.com/tobyxdd/hysteria

WORKDIR /go/src/github.com/tobyxdd/hysteria/cmd

# TODO: Is it necessary to remove "-w -s" to add debugging information?
RUN set -ex \
    && go build -o /go/bin/hysteria -ldflags \
        "-w -s -X main.appVersion=${VERSION} \
        -X main.appCommit=${COMMIT} \
        -X main.appDate=${TIMESTAMP}"

# multi-stage builds to create the final image
FROM alpine:3.12 AS dist

LABEL maintainer="mritd <mritd@linux.com>"

# bash is used for debugging, tzdata is used to add timezone information.
# Install ca-certificates to ensure no CA certificate errors.
#
# Do not try to add the "--no-cache" option when there are multiple "apk"
# commands, this will cause the build process to become very slow.
RUN set -ex \
    && apk upgrade \
    && apk add bash tzdata ca-certificates \
    && rm -rf /var/cache/apk/*

COPY --from=builder /go/bin/hysteria /usr/local/bin/hysteria

ENTRYPOINT ["hysteria"]