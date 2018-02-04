# Copyright (c) 2013 CloudFlare, Inc.

RACE+=--race

PKGNAME=github.com/cloudflare/golibs/circularbuffer
COVEROUT=cover.out

.PHONY: test clean

test:
	@go test $(RACE) -bench=. -v $(PKGNAME)
	@go test -coverprofile=$(COVEROUT) $(PKGNAME) > /dev/null
	@go tool cover -func=$(COVEROUT)|sed 's|^.*/\([^/]*/[^/]*/[^/]*\)$$|\1|g'

clean:
	rm -rf $(COVEROUT)
