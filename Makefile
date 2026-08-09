.PHONY: ui build stressor test clean dev-ui all install uninstall version

BINARY     = mme
VERSION   ?= 0.2.2b
PREFIX     = /opt/vectorcore
BINDIR     = $(PREFIX)/bin
ETCDIR     = $(PREFIX)/etc
LOGDIR     = $(PREFIX)/log
SYSTEMD    = /lib/systemd/system/
LDFLAGS    = -X github.com/vectorcore/mme/internal/buildinfo.Version=$(VERSION)

all: ui build

version:
	@echo $(VERSION)

# Build the React UI (required before `make build`)
ui:
	cd web && ([ -f package-lock.json ] && npm ci || npm install) && npm run build

# Build the Go binary (includes embedded UI if web/dist exists)
build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/mme

# Build the S1AP load generator
stressor:
	go build -o bin/stressor ./cmd/stressor

# Run tests
test:
	go test ./...

# Start Vite dev server (proxies API to localhost:8085)
dev-ui:
	cd web && npm run dev

clean:
	rm -rf bin/$(BINARY) web/dist/

install: build
	install -d $(BINDIR)
	install -d $(ETCDIR)
	install -d $(LOGDIR)

	install -m755 bin/$(BINARY) $(BINDIR)/$(BINARY)

	if [ ! -f $(ETCDIR)/mme.yaml ]; then \
		install -m644 config/mme.yaml $(ETCDIR)/mme.yaml; \
		sed -i 's|# file:.*|file: "$(LOGDIR)/mme.log"|' $(ETCDIR)/mme.yaml; \
	fi

	touch $(LOGDIR)/mme.log
	chmod 644 $(LOGDIR)/mme.log

	install -m644 systemd/vectorcore-mme.service $(SYSTEMD)/vectorcore-mme.service

	systemctl daemon-reload
	systemctl enable vectorcore-mme
	systemctl start vectorcore-mme

uninstall:
	systemctl stop vectorcore-mme || true
	systemctl disable vectorcore-mme || true

	rm -f $(BINDIR)/$(BINARY)
	rm -f $(SYSTEMD)/vectorcore-mme.service

	systemctl daemon-reload
