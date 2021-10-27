package mdns

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apex/log"

	"github.com/apex/log/handlers/cli"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

// Conn represents a mDNS Server
type Conn struct {
	mu      sync.RWMutex
	log     *log.Logger
	socket  *ipv4.PacketConn
	dstAddr *net.UDPAddr

	queryInterval time.Duration
	queries       []query
	zone          Zone

	closed chan interface{}
}

type query struct {
	params      *QueryParam
	serviceAddr string
	resultChan  chan queryResult
	responed    bool
}

type queryResult struct {
	answer dnsmessage.Resource
	addr   net.Addr
}

const (
	inboundBufferSize    = 1024
	defaultQueryInterval = time.Second
	destinationAddress   = "224.0.0.251:5353"
	maxMessageRecords    = 300
	responseTTL          = 120
)

// NewConn establishes a mDNS connection over an existing conn
func NewConn(config *Config) (*Conn, error) {
	conn, err := DefaultPacketConn()
	if err != nil {
		return nil, err
	}

	id = config.StartID

	if config == nil {
		return nil, errNilConfig
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	joinErrCount := 0
	for i := range ifaces {
		if err = conn.JoinGroup(&ifaces[i], &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251)}); err != nil {
			joinErrCount++
		}
	}
	if joinErrCount >= len(ifaces) {
		return nil, errJoiningMulticastGroup
	}

	dstAddr, err := net.ResolveUDPAddr("udp", destinationAddress)
	if err != nil {
		return nil, err
	}

	logger := config.Logger
	if logger == nil {
		logger = &log.Logger{
			Handler: cli.New(os.Stdout),
			Level:   log.DebugLevel,
		}
	}

	// localNames := []string{}
	// for _, l := range config.LocalNames {
	// 	localNames = append(localNames, l+".")
	// }

	c := &Conn{
		queryInterval: defaultQueryInterval,
		queries:       []query{},
		socket:        conn,
		dstAddr:       dstAddr,
		zone:          config.Zone,
		log:           logger,
		closed:        make(chan interface{}),
	}
	if config.QueryInterval != 0 {
		c.queryInterval = config.QueryInterval
	}

	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		wg.Done()
		c.start()
	}()
	wg.Wait()
	return c, nil
}

func DefaultPacketConn() (*ipv4.PacketConn, error) {
	l, err := net.ListenUDP("udp4", ipv4Addr)
	if err != nil {
		panic(err)
	}
	conn := ipv4.NewPacketConn(l)
	return conn, err
}

// Close closes the mDNS Conn
func (c *Conn) Close() error {
	select {
	case <-c.closed:
		return nil
	default:
	}

	if err := c.socket.Close(); err != nil {
		return err
	}

	<-c.closed
	return nil
}

// Query sends mDNS Queries for the following name until
// either the Context is canceled/expires or we get a result
func (c *Conn) Query(ctx context.Context, params *QueryParam) (dnsmessage.ResourceHeader, net.Addr, error) {
	select {
	case <-c.closed:
		return dnsmessage.ResourceHeader{}, nil, errConnectionClosed
	default:
	}

	//serviceAddr := trimDot(params.Service) + "."
	serviceAddr := fmt.Sprintf("%s.%s.", trimDot(params.Service), trimDot(params.Domain))

	resultChan := make(chan queryResult, 100)
	c.mu.Lock()
	q := query{params, serviceAddr, resultChan, false}
	c.queries = append(c.queries, q)
	ticker := time.NewTicker(c.queryInterval)
	c.mu.Unlock()

	defer ticker.Stop()

	c.sendQuestion(serviceAddr)
	go func() {
		<-ctx.Done()
		c.mu.Lock()
		for i := 0; i < len(c.queries); i++ {
			if c.queries[i] == q {
				c.queries = append(c.queries[:i], c.queries[i+1:]...)
				break
			}
		}
		c.mu.Unlock()
	}()
	for {
		select {
		case <-ticker.C:
			c.sendQuestion(serviceAddr)
		case <-c.closed:
			return dnsmessage.ResourceHeader{}, nil, errConnectionClosed
		case res := <-resultChan:
			return res.answer.Header, res.addr, nil
		case <-ctx.Done():
			return dnsmessage.ResourceHeader{}, nil, errContextElapsed
		}
	}
}

func ipToBytes(ip net.IP) (out [4]byte) {
	rawIP := ip.To4()
	if rawIP == nil {
		return
	}

	ipInt := big.NewInt(0)
	ipInt.SetBytes(rawIP)
	copy(out[:], ipInt.Bytes())
	return
}

func interfaceForRemote(remote string) (net.IP, error) {
	conn, err := net.Dial("udp", remote)
	if err != nil {
		return nil, err
	}

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	if err := conn.Close(); err != nil {
		return nil, err
	}

	return localAddr.IP, nil
}

func (c *Conn) sendQuestion(name string) {
	newID := uint16(atomic.AddInt32(&id, 1))
	b := newBuilder(newID)
	b.EnableCompression()
	b.StartQuestions()
	err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
	})
	if err != nil {
		c.log.Warnf("Failed to construct mDNS question %v,Name:%s", err, name)
		return
	}
	rawQuery, err := b.Finish()
	if err != nil {
		c.log.Warnf("Failed to construct mDNS packet %v", err)
		return
	}

	if _, err := c.socket.WriteTo(rawQuery, nil, c.dstAddr); err != nil {
		c.log.Warnf("Failed to send mDNS packet %v", err)
		return
	}
}

func (c *Conn) sendAnswer(rawAnswer []byte, dst net.Addr) {
	if _, err := c.socket.WriteTo(rawAnswer, nil, dst); err != nil {
		c.log.Warnf("Failed to send mDNS packet %v", err)
		return
	}
}

func (c *Conn) start() { //nolint gocognit
	c.log.Info("start")
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		close(c.closed)
	}()

	b := make([]byte, inboundBufferSize)
	p := dnsmessage.Parser{}

	for {
		n, _, src, err := c.socket.ReadFrom(b)
		if err != nil {
			return
		}

		c.mu.RLock()
		defer c.mu.RUnlock()

		h, err := p.Start(b[:n])
		if err != nil {
			c.log.Warnf("Failed to parse mDNS packet %v", err)
			return
		}

		for i := 0; i <= maxMessageRecords; i++ {
			q, err := p.Question()
			if errors.Is(err, dnsmessage.ErrSectionDone) {
				break
			} else if err != nil {
				c.log.Warnf("Failed to parse mDNS packet %v", err)
				return
			}
			if c.zone != nil {
				resources, err := c.zone.Resources(h.ID, q)
				if err != nil {
					log.Warnf("build answer error %v", err)
					return
				}
				c.sendAnswer(resources, src)
			}
		}

		err = p.SkipAllQuestions()
		if err != nil {
			c.log.Warnf("skipAllQuestions error %v", err)
			return
		}

		as, err := p.AllAnswers()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return
		}

		pkEntry := new(ServiceEntry)

		toEntry := func(answer dnsmessage.Resource) {
			switch rr := answer.Body.(type) {
			case *dnsmessage.PTRResource:
				// Create new entry for this
				pkEntry.Name = rr.PTR.String()
			case *dnsmessage.SRVResource:
				pkEntry.Host = rr.Target.String()
				pkEntry.Port = int(rr.Port)
			case *dnsmessage.TXTResource:
				pkEntry.Info = strings.Join(rr.TXT, "|")
				pkEntry.InfoFields = []string{
					answer.Header.Name.String(),
					answer.Header.Type.String(),
					answer.Header.Class.String(),
					strconv.Itoa(int(answer.Header.TTL)),
					strconv.Itoa(int(answer.Header.Length)),
				}
				pkEntry.hasTXT = true
			case *dnsmessage.AResource:
				// Pull out the IP
				addr := net.IPv4(rr.A[0], rr.A[1], rr.A[2], rr.A[3])
				pkEntry.Addr = addr // @Deprecated
				pkEntry.AddrV4 = addr
			case *dnsmessage.AAAAResource:
				// Pull out the IP
				//inp = ensureName(inprogress, answer.Header.Name.String())
				//addr := net.IPv6(rr.A[0], rr.A[1], rr.A[2], rr.A[3])
				//inp.Addr = rr.AAAA // @Deprecated
				//pkEntry.AddrV6 = rr.AAAA
			}
		}
		for i := 0; i <= maxMessageRecords && i < len(as); i++ {
			a := as[i]
			c.log.Debugf("received answer:%v", a)
			if err != nil {
				c.log.Warnf("Failed to parse mDNS packet %v", err)
				return
			}
			toEntry(a)
			for i := len(c.queries) - 1; i >= 0; i-- {
				if c.queries[i].serviceAddr == a.Header.Name.String() {
					if !c.queries[i].responed {
						c.queries[i].resultChan <- queryResult{a, src}
						c.queries[i].responed = true
					}
					//c.queries = append(c.queries[:i], c.queries[i+1:]...)
				}
				if c.queries[i].serviceAddr != pkEntry.Name {
					if pkEntry.complete() {
						c.queries[i].params.Entries <- pkEntry
					}
				}
			}
		}
	}
}

func toServiceEntry(inprogress map[string]*ServiceEntry, answer dnsmessage.Resource) *ServiceEntry {
	var inp *ServiceEntry
	// Map the in-progress responses
	//inprogress := make(map[string]*ServiceEntry)
	switch rr := answer.Body.(type) {
	case *dnsmessage.PTRResource:
		// Create new entry for this
		inp = ensureName(inprogress, rr.PTR.String())

	case *dnsmessage.SRVResource:
		// Check for a target mismatch
		if rr.Target.String() != answer.Header.Name.String() {
			alias(inprogress, answer.Header.Name.String(), rr.Target.String())
		}

		// Get the port
		inp = ensureName(inprogress, answer.Header.Name.String())
		inp.Host = rr.Target.String()
		inp.Port = int(rr.Port)

	case *dnsmessage.TXTResource:
		// Pull out the txt
		inp = ensureName(inprogress, answer.Header.Name.String())
		inp.Info = strings.Join(rr.TXT, "|")
		inp.InfoFields = []string{
			answer.Header.Name.String(),
			answer.Header.Type.String(),
			answer.Header.Class.String(),
			strconv.Itoa(int(answer.Header.TTL)),
			strconv.Itoa(int(answer.Header.Length)),
		}
		inp.hasTXT = true

	case *dnsmessage.AResource:
		// Pull out the IP
		inp = ensureName(inprogress, answer.Header.Name.String())
		addr := net.IPv4(rr.A[0], rr.A[1], rr.A[2], rr.A[3])
		inp.Addr = addr // @Deprecated
		inp.AddrV4 = addr

	case *dnsmessage.AAAAResource:
		// Pull out the IP
		inp = ensureName(inprogress, answer.Header.Name.String())
		//inp.Addr = rr.AAAA // @Deprecated
		//inp.AddrV6 = rr.AAAA
	}
	return inp
}

// ensureName is used to ensure the named node is in progress
func ensureName(inprogress map[string]*ServiceEntry, name string) *ServiceEntry {
	if inp, ok := inprogress[name]; ok {
		return inp
	}
	inp := &ServiceEntry{
		Name: name,
	}
	inprogress[name] = inp
	return inp
}

// alias is used to setup an alias between two entries
func alias(inprogress map[string]*ServiceEntry, src, dst string) {
	srcEntry := ensureName(inprogress, src)
	inprogress[dst] = srcEntry
}
