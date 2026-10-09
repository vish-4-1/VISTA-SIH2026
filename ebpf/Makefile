# Build and run the VISTA libbpf CO-RE collector.
DOCKER_COMPOSE ?= docker compose

run:
	$(DOCKER_COMPOSE) --profile ebpf -f ../topology/docker-compose.yml up --build vista-ebpf-monitor

logs:
	$(DOCKER_COMPOSE) --profile ebpf -f ../topology/docker-compose.yml logs -f vista-ebpf-monitor

.PHONY: run logs
