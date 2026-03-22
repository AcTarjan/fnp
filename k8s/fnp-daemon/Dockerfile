FROM fnp-base:v1

WORKDIR /root

COPY build/fnp-daemon /root/fnp-daemon
COPY conf/fnp.yaml /root/fnp.yaml
COPY conf/fnp-tap.yaml /root/fnp-tap.yaml
COPY k8s/fnp-daemon/start.sh /usr/local/bin/start-fnp-daemon.sh

RUN chmod +x /root/fnp-daemon /usr/local/bin/start-fnp-daemon.sh

ENTRYPOINT ["/bin/bash", "-lc", "/usr/local/bin/start-fnp-daemon.sh"]
