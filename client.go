package mdns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ServiceEntry is returned after we query for a service
type ServiceEntry struct {
	Name       string
	Host       string
	AddrV4     net.IP
	AddrV6     net.IP
	Port       int
	Info       string
	InfoFields []string

	Addr net.IP // @Deprecated

	hasTXT bool
}

// complete is used to check if we have all the info we need
func (s *ServiceEntry) complete() bool {
	return (s.AddrV4 != nil || s.AddrV6 != nil || s.Addr != nil) && s.Port != 0 && s.hasTXT
}

func (s *ServiceEntry) String() string {
	fields := make([]string, 0)
	if s.Name != "" {
		fields = append(fields, fmt.Sprintf("Name:%s", s.Name))
	}
	if s.Host != "" {
		fields = append(fields, fmt.Sprintf("Host:%s", s.Host))
	}
	if s.AddrV4 != nil {
		fields = append(fields, fmt.Sprintf("AddrV4:%v", s.AddrV4))
	}
	if s.AddrV6 != nil {
		fields = append(fields, fmt.Sprintf("Host:%v", s.AddrV6))
	}
	if s.Port != 0 {
		fields = append(fields, fmt.Sprintf("Port:%d", s.Port))
	}
	if s.Info != "" {
		fields = append(fields, fmt.Sprintf("Info:%s", s.Info))
	}
	if s.InfoFields != nil && len(s.InfoFields) != 0 {
		fields = append(fields, fmt.Sprintf("InfoFields:%v", s.InfoFields))
	}
	fields = append(fields, fmt.Sprintf("hasTXT:%v", s.hasTXT))
	return strings.Join(fields, ",")
}

// QueryParam is used to customize how a Lookup is performed
type QueryParam struct {
	Service             string             // Service to lookup
	Domain              string             // Lookup domain, default "local"
	Timeout             time.Duration      // Lookup timeout, default 1 second
	Interface           *net.Interface     // Multicast interface to use
	Entries             chan *ServiceEntry // Entries Channel
	WantUnicastResponse bool               // Unicast response desired, as per 5.4 in RFC
}

// DefaultParams is used to return a default set of QueryParam's
func DefaultParams(service string) *QueryParam {
	return &QueryParam{
		Service:             service,
		Domain:              "local",
		Timeout:             time.Second,
		Entries:             make(chan *ServiceEntry),
		WantUnicastResponse: false, // TODO(reddaly): Change this default.
	}
}

// Query looks up a given service, in a domain, waiting at most
// for a timeout before finishing the query. The results are streamed
// to a channel. Sends will not block, so clients should make sure to
// either read or buffer.
func Query(params *QueryParam) (dnsmessage.ResourceHeader, net.Addr, error) {
	// Create a new client
	client, err := newClient(params.Interface)
	if err != nil {
		return dnsmessage.ResourceHeader{}, nil, err
	}
	//defer client.Close()

	// Set the multicast interface
	// if params.Interface != nil {
	// 	if err := client.setInterface(params.Interface); err != nil {
	// 		return err
	// 	}
	// }

	// Ensure defaults are set
	if params.Domain == "" {
		params.Domain = "local"
	}
	if params.Timeout == 0 {
		params.Timeout = time.Second
	}

	// Run the query
	return client.query(params)
}

// Client provides a query interface that can be used to
// search for service providers using mDNS
type client struct {
	conn *Conn

	closed    bool
	closedCh  chan struct{} // TODO(reddaly): This doesn't appear to be used.
	closeLock sync.Mutex
}

// NewClient creates a new mdns Client that can be used to query
// for records
func newClient(iface *net.Interface) (*client, error) {
	// TODO(reddaly): At least attempt to bind to the port required in the spec.
	// Create a IPv4 listener
	conn, err := NewConn(&Config{Zone: nil})
	if err != nil {
		return nil, fmt.Errorf("[ERR] mdns: Failed to create client conn: %v", err)
	}

	c := &client{
		conn:     conn,
		closedCh: make(chan struct{}),
	}
	return c, nil
}

func (c *client) getIsClosed() bool {
	c.closeLock.Lock()
	defer c.closeLock.Unlock()
	return c.closed
}

// Close is used to cleanup the client
func (c *client) Close() error {
	c.closeLock.Lock()
	defer c.closeLock.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	close(c.closedCh)

	if c.conn != nil {
		c.conn.Close()
	}

	return nil
}

// query is used to perform a lookup and stream results
func (c *client) query(params *QueryParam) (dnsmessage.ResourceHeader, net.Addr, error) {
	ctx, _ := context.WithCancel(context.Background())
	return c.conn.Query(ctx, params)
}
