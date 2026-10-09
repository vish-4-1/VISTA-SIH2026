FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       linux-tools-generic clang llvm gcc make pkg-config libbpf-dev libelf-dev zlib1g-dev python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN bpftool_path="$(find /usr/lib/linux-tools -type l -name bpftool -print -quit)" \
    && test -x "$bpftool_path" \
    && ln -s "$bpftool_path" /usr/local/bin/bpftool

WORKDIR /opt/vista-ebpf
COPY vista_ipsec_monitor.bpf.c collector_server.py event_window.py libbpf_loader.c ./
RUN gcc -O2 -Wall -Wextra -Werror libbpf_loader.c -o vista_libbpf_loader \
    $(pkg-config --cflags --libs libbpf)

EXPOSE 8765
CMD ["python3", "collector_server.py", "--host", "0.0.0.0", "--port", "8765"]
