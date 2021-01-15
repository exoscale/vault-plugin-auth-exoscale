include go.mk/init.mk
include go.mk/public.mk

PACKAGE := github.com/exoscale/vault-plugin-auth-exoscale

PROJECT_URL := https://$(PACKAGE)

GO_LD_FLAGS := -ldflags "-s -w -X $(PACKAGE)/version.Version=${VERSION} \
									-X $(PACKAGE)/version.Commit=${GIT_REVISION}"
GO_MAIN_PKG_PATH := ./cmd/vault-plugin-auth-exoscale
EXTRA_ARGS := -parallel 3 -count=1 -failfast
