// Package mdns implements mDNS (multicast DNS)
package mdns

import (
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	ipv4mdns              = "224.0.0.251"
	ipv6mdns              = "ff02::fb"
	mdnsPort              = 5353
	forceUnicastResponses = false
)

var (
	ipv4Addr = &net.UDPAddr{
		IP:   net.ParseIP(ipv4mdns),
		Port: mdnsPort,
	}
	ipv6Addr = &net.UDPAddr{
		IP:   net.ParseIP(ipv6mdns),
		Port: mdnsPort,
	}
)

const (
	// defaultTTL is the default TTL value in returned DNS records in seconds.
	defaultTTL = 120
	TypeANY    = dnsmessage.Type(255)
)

var id = int32(0)

func newBuilder(id uint16) *dnsmessage.Builder {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:       id,
		Response: true,
	})
	return &b
}
