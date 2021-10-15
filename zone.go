package mdns

import (
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

/*
(Question.Name->{Type->[Resources]})

_services._dns-sd._udp.<domain>(enumAddrName) -> {
	TypePTR->[TypePTR]
}

*/

// Zone is the interface used to integrate with the server and
// to serve records dynamically
type Zone interface {
	// Records returns DNS records in response to a DNS question.
	Resources(id uint16, q dnsmessage.Question) ([]byte, error)
}

// MDNSService is used to export a named service by implementing a Zone
type MDNSService struct {
	Instance string   // Instance name (e.g. "hostService name")
	Service  string   // Service name (e.g. "_http._tcp.")
	Domain   string   // If blank, assumes "local"
	HostName string   // Host machine DNS name (e.g. "mymachine.net.")
	Port     int      // Service Port
	IPs      []net.IP // IP addresses for the service's host
	TXT      []string // Service TXT records

	serviceAddrName  dnsmessage.Name // Fully qualified service address
	instanceAddrName dnsmessage.Name // Fully qualified instance address
	enumAddrName     dnsmessage.Name // _services._dns-sd._udp.<domain>
}

// validateFQDN returns an error if the passed string is not a fully qualified
// hdomain name (more specifically, a hostname).
func validateFQDN(s string) error {
	if len(s) == 0 {
		return fmt.Errorf("FQDN must not be blank")
	}
	if s[len(s)-1] != '.' {
		return fmt.Errorf("FQDN must end in period: %s", s)
	}
	// TODO(reddaly): Perform full validation.

	return nil
}

// NewMDNSService returns a new instance of MDNSService.
//
// If domain, hostName, or ips is set to the zero value, then a default value
// will be inferred from the operating system.
//
// TODO(reddaly): This interface may need to change to account for "unique
// record" conflict rules of the mDNS protocol.  Upon startup, the server should
// check to ensure that the instance name does not conflict with other instance
// names, and, if required, select a new name.  There may also be conflicting
// hostName A/AAAA records.
func NewMDNSService(instance, service, domain, hostName string, port int, ips []net.IP, txt []string) (*MDNSService, error) {
	// Sanity check inputs
	if instance == "" {
		return nil, fmt.Errorf("missing service instance name")
	}
	if service == "" {
		return nil, fmt.Errorf("missing service name")
	}
	if port == 0 {
		return nil, fmt.Errorf("missing service port")
	}

	// Set default domain
	if domain == "" {
		domain = "local."
	}
	if err := validateFQDN(domain); err != nil {
		return nil, fmt.Errorf("domain %q is not a fully-qualified domain name: %v", domain, err)
	}

	// Get host information if no host is specified.
	if hostName == "" {
		var err error
		hostName, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("could not determine host: %v", err)
		}
		hostName = fmt.Sprintf("%s.", hostName)
	}
	if err := validateFQDN(hostName); err != nil {
		return nil, fmt.Errorf("hostName %q is not a fully-qualified domain name: %v", hostName, err)
	}

	if len(ips) == 0 {
		var err error
		ips, err = net.LookupIP(hostName)
		if err != nil {
			// Try appending the host domain suffix and lookup again
			// (required for Linux-based hosts)
			tmpHostName := fmt.Sprintf("%s%s", hostName, domain)

			ips, err = net.LookupIP(tmpHostName)

			if err != nil {
				return nil, fmt.Errorf("could not determine host IP addresses for %s", hostName)
			}
		}
	}
	for _, ip := range ips {
		if ip.To4() == nil && ip.To16() == nil {
			return nil, fmt.Errorf("invalid IP address in IPs list: %v", ip)
		}
	}

	serviceAddrName := dnsmessage.MustNewName(fmt.Sprintf("%s.%s.", trimDot(service), trimDot(domain)))
	instanceAddrName := dnsmessage.MustNewName(fmt.Sprintf("%s.%s.%s.", instance, trimDot(service), trimDot(domain)))
	enumAddrName := dnsmessage.MustNewName(fmt.Sprintf("_services._dns-sd._udp.%s.", trimDot(domain)))

	return &MDNSService{
		Instance:         instance,
		Service:          service,
		Domain:           domain,
		HostName:         hostName,
		Port:             port,
		IPs:              ips,
		TXT:              txt,
		serviceAddrName:  serviceAddrName,
		instanceAddrName: instanceAddrName,
		enumAddrName:     enumAddrName,
	}, nil
}

// trimDot is used to trim the dots from the start or end of a string
func trimDot(s string) string {
	return strings.Trim(s, ".")
}

// Records returns DNS records in response to a DNS question.
func (m *MDNSService) Resources(id uint16, q dnsmessage.Question) ([]byte, error) {
	builder := newBulider(id)
	builder.EnableCompression()
	err := builder.StartAnswers()
	if err != nil {
		panic(err)
	}
	//log.Infof("%s,%s,%s,%s,%s", q.Name.String(), m.enumAddrName.String(), m.serviceAddrName.String(),
	//	m.instanceAddrName.String(), m.HostName)
	switch q.Name.String() {
	case m.enumAddrName.String():
		m.serviceEnum(builder, q)
	case m.serviceAddrName.String():
		m.serviceRecords(builder, q)
	case m.instanceAddrName.String():
		m.instanceRecords(builder, q)
	case m.HostName:
		if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA {
			m.instanceRecords(builder, q)
		}
	default:
		return nil, nil
	}
	return builder.Finish()
}

func (m *MDNSService) serviceEnum(builder *dnsmessage.Builder, q dnsmessage.Question) {
	switch q.Type {
	case dnsmessage.TypePTR:
		builder.PTRResource(
			dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  q.Type,
				Class: q.Class,
				TTL:   defaultTTL,
			},
			dnsmessage.PTRResource{
				PTR: m.enumAddrName,
			},
		)
	}
}

/*
<instance>.<domain>.(serviceAddrName) -> {
	TypeANY ->[TypePTR,TypeSRV,TypeTXT,TypeA,TypeAAAA]
}
*/
// serviceRecords is called when the query matches the service name
func (m *MDNSService) serviceRecords(builder *dnsmessage.Builder, q dnsmessage.Question) {
	switch q.Type {
	case dnsmessage.TypePTR:
		// Build a PTR response for the service
		builder.PTRResource(
			dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  q.Type,
				Class: q.Class,
				TTL:   defaultTTL,
			},
			dnsmessage.PTRResource{
				PTR: m.instanceAddrName,
			},
		)

		// Get the instance records
		m.instanceRecords(builder, dnsmessage.Question{
			Name: m.instanceAddrName,
			Type: TypeANY,
		})
	}
}

func ip4ToByte(ip4 net.IP) [4]byte {
	b := []byte(ip4)
	return [4]byte{b[0], b[1], b[2], b[3]}
}
func ip16ToByte(ip16 net.IP) [16]byte {
	b := []byte(ip16)
	return [16]byte{b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]}
}

/*
<instance>.<service>.<domain>.(instanceAddrName) -> {
	TypeANY->[TypeSRV,TypeA,TypeAAAA,TypeTXT],
	TypeA->[TypeA],
	TypeAAAA->[TypeAAAA],
	TypeSRV->[TypeSRV,TypeA,TypeAAAA],
	TypeTXT->[TypeTXT]
}
*/
// serviceRecords is called when the query matches the instance name
func (m *MDNSService) instanceRecords(builder *dnsmessage.Builder, q dnsmessage.Question) {
	switch q.Type {
	case TypeANY:
		m.instanceRecords(builder, dnsmessage.Question{
			Name: m.instanceAddrName,
			Type: dnsmessage.TypeSRV,
		})

		// Add the TXT record
		m.instanceRecords(builder, dnsmessage.Question{
			Name: m.instanceAddrName,
			Type: dnsmessage.TypeTXT,
		})
		return
	case dnsmessage.TypeA:
		for _, ip := range m.IPs {
			if ip4 := ip.To4(); ip4 != nil {
				builder.AResource(
					dnsmessage.ResourceHeader{
						Name:  q.Name,
						Type:  q.Type,
						Class: q.Class,
						TTL:   defaultTTL,
					},
					dnsmessage.AResource{
						A: ip4ToByte(ip4),
					},
				)
			}
		}
		return

	case dnsmessage.TypeAAAA:
		for _, ip := range m.IPs {
			if ip.To4() != nil {
				// TODO(reddaly): IPv4 addresses could be encoded in IPv6 format and
				// putinto AAAA records, but the current logic puts ipv4-encodable
				// addresses into the A records exclusively.  Perhaps this should be
				// configurable?
				continue
			}

			if ip16 := ip.To16(); ip16 != nil {

				builder.AAAAResource(
					dnsmessage.ResourceHeader{
						Name:  q.Name,
						Type:  q.Type,
						Class: q.Class,
						TTL:   defaultTTL,
					},
					dnsmessage.AAAAResource{
						AAAA: ip16ToByte(ip16),
					},
				)
			}
		}
		return

	case dnsmessage.TypeSRV:
		// Create the SRV Record
		hostName, _ := dnsmessage.NewName(m.HostName)
		builder.SRVResource(
			dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  q.Type,
				Class: q.Class,
				TTL:   defaultTTL,
			},
			dnsmessage.SRVResource{
				Priority: 10,
				Weight:   1,
				Port:     uint16(m.Port),
				Target:   hostName,
			},
		)

		// Add the A record
		m.instanceRecords(builder, dnsmessage.Question{
			Name: m.instanceAddrName,
			Type: dnsmessage.TypeA,
		})

		// Add the AAAA record
		m.instanceRecords(builder, dnsmessage.Question{
			Name: m.instanceAddrName,
			Type: dnsmessage.TypeAAAA,
		})
		return

	case dnsmessage.TypeTXT:
		builder.TXTResource(
			dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  q.Type,
				Class: q.Class,
				TTL:   defaultTTL,
			},
			dnsmessage.TXTResource{
				TXT: m.TXT,
			},
		)
		return
	default:
		// Get the SRV, which includes A and AAAA
		m.instanceRecords(builder, dnsmessage.Question{
			Name: m.instanceAddrName,
			Type: dnsmessage.TypeSRV,
		})

		// Add the TXT record
		m.instanceRecords(builder, dnsmessage.Question{
			Name: m.instanceAddrName,
			Type: dnsmessage.TypeTXT,
		})
		return
	}
}
