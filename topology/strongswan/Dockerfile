FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        strongswan \
        strongswan-swanctl \
        iproute2 \
        iputils-ping \
        tcpdump \
        netcat-openbsd \
        ca-certificates \
        python3 \
        python3-pip \
        curl \
        iperf3 \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/sbin/vista-strongswan-entrypoint
RUN sed -i 's/\r$//' /usr/local/sbin/vista-strongswan-entrypoint \
    && chmod 0755 /usr/local/sbin/vista-strongswan-entrypoint

ENTRYPOINT ["/usr/local/sbin/vista-strongswan-entrypoint"]
