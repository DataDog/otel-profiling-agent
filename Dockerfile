FROM debian:testing

WORKDIR /agent

# cross_debian_arch: amd64 or arm64
# cross_pkg_arch: x86-64 or aarch64
RUN cross_debian_arch=$(uname -m | sed -e 's/aarch64/amd64/'  -e 's/x86_64/arm64/'); \
    cross_pkg_arch=$(uname -m | sed -e 's/aarch64/x86-64/' -e 's/x86_64/aarch64/'); \
    apt-get update -y && \
    apt-get dist-upgrade -y && \
    apt-get install -y wget make git clang-16 golang unzip sudo \
        gcc-${cross_pkg_arch}-linux-gnu libc6-${cross_debian_arch}-cross && \
    apt-get clean autoclean && \
    apt-get autoremove --yes

RUN wget -qO- https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b $(go env GOPATH)/bin v1.56.2

# gRPC dependencies
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.31.0
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0

RUN                                                                                \
  PB_URL="https://github.com/protocolbuffers/protobuf/releases/download/v24.4/";   \
  PB_FILE="protoc-24.4-linux-x86_64.zip";                                      \
  INSTALL_DIR="/usr/local";                                                        \
                                                                                   \
  wget -q "$PB_URL/$PB_FILE"                                                       \
    && unzip "$PB_FILE" -d "$INSTALL_DIR" 'bin/*' 'include/*'                      \
    && chmod +xr "$INSTALL_DIR/bin/protoc"                                         \
    && find "$INSTALL_DIR/include" -type d -exec chmod +x {} \;                    \
    && find "$INSTALL_DIR/include" -type f -exec chmod +r {} \;                    \
    && rm "$PB_FILE"

# The docker image is built as root - make binaries available to user.
RUN mv /root/go/bin/* /usr/local/bin/

ENV GOCACHE=/agent/.cache

RUN useradd -ms /bin/bash build
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN adduser build sudo

USER build
