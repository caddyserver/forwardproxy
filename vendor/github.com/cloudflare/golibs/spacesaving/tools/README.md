Tools for validating spacesaving.Rate algorithm
-----------

Testing github.com/cloudflare/golibs/spacesaving/rate.go ain't
easy. Here are a few tools that can be used to make sure the thing
actually works.

First we need some data. Not having a better idea we use a pcap dump
of a DNS traffic as test data. You can create a capture yourself:

    $ tcpdump -n -s0 -w dnstraffic.pcap -iany -c10000 udp and dst port 53

Having that type `make`, you should compile four binaries:

 - `readpcap`: Prepares data for further steps: reads pcap and prints
   valid dns packets on stdout.

 - `main`: Reads data from stdin and counts rates using
   spacesaving.Rate implementation.

 - `perfect`: Reads data from stdin and counts rates using ideal
  ewma.Rate implementation, memory consumption is unlimited.

 - `topdns`: Uses pcap library to listen on a live network card and
  prints rates of captured dns requests.

There is also a python script `compare.py` that can be used to compare
two sets of results against each other.

The steps are:

1) Use `./readpcap` tool to read the pcap and produce consumalbe data
stream.

2) Use `./perfect` to count real packet rates and print them at the
time of a last packet. This uses ideal implementation, and the memory
usage is unconstrained.

3) Use `./main` to count approx packet rates using our
spacesaving.Rate implementation.

4) Use `compare.py` to compare the results against each other.

There is a handy script `go.sh` that does all that for you. For
example to ask for rates of top 16 things:

    $ ./go.sh dnstraffic.pcap 16

With a bit of luck packet ranges given by `main` will cover the real
packet rates as returned by `perfect` tool.
