package mdns

import (
	"net"
	"os"
	"sync"
	"testing"

	"github.com/apex/log"
)

func TestMdns(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		host, _ := os.Hostname()
		info := []string{"My awesome service"}
		service, err := NewMDNSService(host, "test.local", "", "", 8000, nil, info)
		if err != nil {
			panic(err)
		}

		// Create the mDNS server, defer shutdown
		server, _ := NewServer(&Config{Zone: service})
		wg.Done()
		defer server.Shutdown()
		done := make(chan struct{})
		<-done
	}()
	go func() {
		entriesCh := make(chan *ServiceEntry, 4)
		go func() {
			for entry := range entriesCh {
				log.Infof("Got new entry: %v\n", entry)
			}
		}()
		
		wg.Wait()
		if err := Query(&QueryParam{
			Service: "test.local",
			Entries: entriesCh,
		}); err != nil {
			log.Errorf("query error: %v", err)
		}
		// Start the lookup

		done := make(chan struct{})
		<-done
		//close(entriesCh)

	}()

	done := make(chan struct{})
	<-done
}

func TestGetIf(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	for _, i := range ifaces {
		log.Infof("%v", i.Name)
	}
}
