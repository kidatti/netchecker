BINARY := netchecker
VERSION := $(shell git describe --tags 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)
DIST_DIR := dist

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: build release clean

build:
	go build -ldflags '$(LDFLAGS)' -o $(BINARY) .

release: clean
	@mkdir -p $(DIST_DIR)
	@$(foreach platform,$(PLATFORMS), \
		$(eval OS := $(word 1,$(subst /, ,$(platform)))) \
		$(eval ARCH := $(word 2,$(subst /, ,$(platform)))) \
		$(eval EXT := $(if $(filter windows,$(OS)),.exe,)) \
		$(eval OUT := $(BINARY)-$(VERSION)-$(OS)-$(ARCH)) \
		echo "Building $(OUT)..." && \
		GOOS=$(OS) GOARCH=$(ARCH) go build -ldflags '$(LDFLAGS)' -o $(DIST_DIR)/$(OUT)/$(BINARY)$(EXT) . && \
		$(if $(filter windows,$(OS)), \
			cd $(DIST_DIR) && zip -r $(OUT).zip $(OUT) && rm -rf $(OUT) && cd .., \
			cd $(DIST_DIR) && tar czf $(OUT).tar.gz $(OUT) && rm -rf $(OUT) && cd .. \
		) && \
	) true

clean:
	rm -f $(BINARY)
	rm -rf $(DIST_DIR)
