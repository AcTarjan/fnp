FROM rockylinux:9.3
LABEL authors="guoyongkang"

RUN yum install yum-utils  -y\
    && yum config-manager --set-enabled crb \
    && yum update -y  \
    && yum install -y procps-ng iproute iputils ethtool vim libpcap-devel ncurses bash-completion
