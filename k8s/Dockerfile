FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    ethtool \
    iproute2 \
    iputils-ping \
    libnuma1 \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root

COPY k8s/fnp-daemon /root/fnp-daemon
COPY k8s/conf/fnp.yaml /root/fnp.yaml
COPY k8s/conf/fnp-tap.yaml /root/fnp-tap.yaml
COPY k8s/start.sh /root/start.sh

RUN chmod +x /root/fnp-daemon /root/start.sh

ENTRYPOINT ["/root/start.sh"]
