# Copyright (c) 2014 CloudFlare, Inc.

RACE+=--race

COVEROUT=cover.out

.PHONY: test clean

test:
	@go test -coverprofile=$(COVEROUT) .
	@go tool cover -func=$(COVEROUT)|sed 's|^.*/\([^/]*/[^/]*/[^/]*\)$$|\1|g'
	@go test -bench=. -v . -run=nil

clean:
	rm -rf $(COVEROUT)
