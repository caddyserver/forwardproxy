# Copyright (c) 2013 CloudFlare, Inc.

RACE+=--race

COVEROUT=cover.out

.PHONY: test clean

test:
	@go test $(RACE) -bench=. -v .
	@go test -coverprofile=$(COVEROUT) . > /dev/null
	@go tool cover -func=$(COVEROUT)|sed 's|^.*/\([^/]*/[^/]*/[^/]*\)$$|\1|g'

clean:
	rm -rf $(COVEROUT)
