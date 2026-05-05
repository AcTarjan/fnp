# Dockerfile.fnp-perf
# FNP performance test image for LDP (same-node) and cross-node tests.
# Based on the existing fnp-node-perf base image that has tini + runtime deps.
ARG BASE_IMAGE=fnp-node-perf:20260501-113630
FROM ${BASE_IMAGE}

WORKDIR /root

# Install python3 (needed by analyze_rtt.py)
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends python3 && \
    rm -rf /var/lib/apt/lists/*

COPY bin/fnp-daemon          /root/fnp-daemon
COPY bin/fnp_node_perf_demo  /root/fnp-node-perf-demo
COPY bin/run_perf.sh         /root/run_perf.sh
COPY bin/analyze_rtt.py      /root/analyze_rtt.py
COPY conf/                   /root/conf/

RUN chmod +x /root/fnp-daemon \
    /root/fnp-node-perf-demo \
    /root/run_perf.sh \
    /root/analyze_rtt.py

ENTRYPOINT ["/usr/bin/tini", "-v", "--"]
CMD ["/bin/bash"]
