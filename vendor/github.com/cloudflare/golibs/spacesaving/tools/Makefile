
all: main perfect readpcap topdns

GOLIBS=$(GOPATH)/src/github.com/cloudflare/golibs

main: main.go $(GOLIBS)/spacesaving/*go
	go build main.go

perfect: perfect.go $(GOLIBS)/ewma/*go
	go build perfect.go

readpcap: readpcap.go $(GOPATH)/src/github.com/miekg/pcap/*go $(GOPATH)/src/github.com/miekg/dns/*go
	go build readpcap.go

topdns: topdns.go $(GOLIBS)/spacesaving/*go $(GOPATH)/src/github.com/miekg/pcap/*go
	go build topdns.go

clean:
	rm -f main perfect readpcap topdns

