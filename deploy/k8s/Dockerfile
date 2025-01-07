FROM baseimage:v1
LABEL authors="guoyongkang"

WORKDIR /root

COPY dpdkSlaveApp .
COPY start.sh .
RUN chmod +x start.sh dpdkSlaveApp

ENTRYPOINT ["/bin/bash", "-c", "./start.sh"]

#ENTRYPOINT ["/bin/bash", "-c", "tail -f /dev/null"]
