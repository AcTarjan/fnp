FROM ubuntu:24.04 AS fnp-build

LABEL org.opencontainers.image.title="fnp-build" \
    org.opencontainers.image.version="v1" \
    org.opencontainers.image.description="Build image for fnp and DPDK"

ENV DEBIAN_FRONTEND=noninteractive
ENV DPDK_INSTALL_PREFIX=/opt/dpdk

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    cmake \
    curl \
    ethtool \
    gcc \
    git \
    golang-go \
    iproute2 \
    iputils-ping \
    libelf-dev \
    libnl-3-dev \
    libnl-route-3-dev \
    libnuma-dev \
    libpcap-dev \
    libssl-dev \
    make \
    pkg-config \
    procps \
    python-is-python3 \
    python3 \
    python3-pip \
    python3-venv \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

COPY deps/dpdk /tmp/fnp/deps/dpdk

RUN bash /tmp/fnp/deps/dpdk/build.sh \
    && rm -rf /tmp/fnp

WORKDIR /root

FROM ubuntu:24.04 AS fnp-base

LABEL org.opencontainers.image.title="fnp-base" \
    org.opencontainers.image.version="v1" \
    org.opencontainers.image.description="Runtime base image for fnp-daemon with DPDK installed"

ENV DEBIAN_FRONTEND=noninteractive
ENV DPDK_INSTALL_PREFIX=/opt/dpdk
ENV LD_LIBRARY_PATH=/opt/dpdk/lib/x86_64-linux-gnu:/opt/dpdk/lib64:/opt/dpdk/lib

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    ethtool \
    iproute2 \
    iputils-ping \
    libelf1t64 \
    libnl-3-200 \
    libnl-route-3-200 \
    libnuma1 \
    libpcap0.8t64 \
    libssl3t64 \
    procps \
    python-is-python3 \
    python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=fnp-build /opt/dpdk /opt/dpdk

WORKDIR /root
