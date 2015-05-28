# go-bfd

Bidirectional Forwarding Detection library for Go

## Description

Implementation of Bidirectional Forwarding Detection (BFD)

* Based on:
  * Bidirectional Forwarding Detection [RFC5880](http://tools.ietf.org/html/rfc5880)
  * BFD for IPv4 and IPv6 (Single Hop) [RFC5881](http://tools.ietf.org/html/rfc5881)

BFD Control packets MUST be transmitted in UDP packets with
destination port 3784, within an IPv4 or IPv6 packet.  The source
port MUST be in the range 49152 through 65535
