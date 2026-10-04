FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv python3 sudo openssh-server iproute2 iputils-ping \
 && rm -rf /var/lib/apt/lists/*
CMD ["/sbin/init"]
