# catnip

catnip is a tiny non-libpcap based network 'remote mirroring' suite (currently only for Linux) which when compiled and stripped the binary is smaller than 20kiB. This makes it very suitable for embedded environments where a libpcap based tool, typically 100kiB for just libpcap and 500kiB for tcpdump, would be simply too large. catnip is generally parameter compatible with tcpdump and what makes catnip stand out from other small packet capturing tools is that also supports BPF filtering.

Whilst putting together a buildroot based Linux environment for my Linksys WAG54G I was disappointed to find that a compiled libpcap/tcpdump was just too large for the 4MiB flash I was limited to. Digging around I could not find any other filtering supporting micro-sized libpcap-less capturing tools so set out to write my own, and this is the result of my efforts.

The source code and (hopefully) better documentation for 'catnip' is at https://github.com/jimdigriz/catnip

## Features

 * GNU Version 3 License
 * generally parameter compatible to tcpdump
 * Linux Socket Filter (a la BPF) support
 * no library dependencies
 * privilege dropping
 * presents the remote interface (with a remote applied BPF filter) locally via TUN/TAP; meaning you just 'tcpdump' on a local interface as if you were on the remote device

## Issues

 * sniffing promiscuously on an 802.11 interface gives some interesting output
 * support mmap'd ring buffer capturing under Linux
 * simple verbosity, Layer 2 (Ethernet), Layer 3 (IPv4 and IPv6) and Layer 4 (TCP and UDP) decoder
 * Mac OS X/*BSD support
 * trigger rules to stop capturing, 'x' packets and/or 'y' seconds
 * add minimum boundary for snaplen to be (L2 header)

# Running the Server

To run the server type as root:

    tcpsvd -vv 0 34343 ./catnipd

# Running the Client

Client commands (`catnip -h` provides usage help):

## list the interfaces at the remote end

    ./catnip -H server -D

## plain packet mirroring

    sudo ./catnip -H server -i eth0

You will now find a local `tun0` interface for you to capture on with:

    sudo tcpdump -i tap0 -n

## packet mirroring with a filter

    sudo ./catnip -H server -i ppp0 'host www.sixxs.net'

You will now find a local `tun0` interface for you to capture on with:

    sudo tcpdump -i tun0 -n

This one will only mirror packets that match the filter `host www.sixxs.net` (which has IPv4 and IPv6 addresses).
