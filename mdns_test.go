package mdns

import (
	"bytes"
	"os"
	"sync"
	"testing"

	"github.com/apex/log"
	"golang.org/x/net/dns/dnsmessage"
)

func TestMdns(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		host, _ := os.Hostname()
		info := []string{"My awesome service"}
		service, err := NewService(host, "test", "", "", 8000, nil, info)
		if err != nil {
			panic(err)
		}

		// Create the mDNS server, defer shutdown
		server, _ := NewServer(&Config{Zone: service})
		wg.Done()
		defer server.Close()
		done := make(chan struct{})
		<-done
	}()
	params := DefaultParams("test")
	go func() {
		for entry := range params.Entries {
			log.Infof("entry:%v", entry)
		}
	}()
	go func() {
		// Create the mDNS server, defer shutdown
		wg.Wait()
		h, src, err := Query(params)
		log.Infof("header %v", h)
		log.Infof("addr %v", src)
		log.Infof("err %v", err)
		done := make(chan struct{})
		<-done

	}()

	done := make(chan struct{})
	<-done
}
func largeTestMsg() dnsmessage.Message {
	name := dnsmessage.MustNewName("foo.bar.example.com.")
	return dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Questions: []dnsmessage.Question{
			{
				Name:  name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
		Answers: []dnsmessage.Resource{
			{
				dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
				&dnsmessage.AResource{[4]byte{127, 0, 0, 1}},
			},
			{
				dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
				&dnsmessage.AResource{[4]byte{127, 0, 0, 2}},
			},
			{
				dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
				},
				&dnsmessage.AAAAResource{[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
			},
			{
				dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeCNAME,
					Class: dnsmessage.ClassINET,
				},
				&dnsmessage.CNAMEResource{dnsmessage.MustNewName("alias.example.com.")},
			},
			{
				dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeSOA,
					Class: dnsmessage.ClassINET,
				},
				&dnsmessage.SOAResource{
					NS:      dnsmessage.MustNewName("ns1.example.com."),
					MBox:    dnsmessage.MustNewName("mb.example.com."),
					Serial:  1,
					Refresh: 2,
					Retry:   3,
					Expire:  4,
					MinTTL:  5,
				},
			},
			{
				dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypePTR,
					Class: dnsmessage.ClassINET,
				},
				&dnsmessage.PTRResource{dnsmessage.MustNewName("ptr.example.com.")},
			},
			{
				dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeMX,
					Class: dnsmessage.ClassINET,
				},
				&dnsmessage.MXResource{
					7,
					dnsmessage.MustNewName("mx.example.com."),
				},
			},
			{
				dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeSRV,
					Class: dnsmessage.ClassINET,
				},
				&dnsmessage.SRVResource{
					8,
					9,
					11,
					dnsmessage.MustNewName("srv.example.com."),
				},
			},
			{
				dnsmessage.ResourceHeader{
					Name:  name,
					Type:  TypeANY,
					Class: dnsmessage.ClassINET,
				},
				&dnsmessage.UnknownResource{
					Type: TypeANY,
					Data: []byte{42, 0, 43, 44},
				},
			},
		},
		Authorities: []dnsmessage.Resource{
			{
				dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeNS,
					Class: dnsmessage.ClassINET,
				},
				&dnsmessage.NSResource{dnsmessage.MustNewName("ns1.example.com.")},
			},
			{
				dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeNS,
					Class: dnsmessage.ClassINET,
				},
				&dnsmessage.NSResource{dnsmessage.MustNewName("ns2.example.com.")},
			},
		},
		Additionals: []dnsmessage.Resource{
			{
				dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeTXT,
					Class: dnsmessage.ClassINET,
				},
				&dnsmessage.TXTResource{[]string{"So Long, and Thanks for All the Fish"}},
			},
			{
				dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeTXT,
					Class: dnsmessage.ClassINET,
				},
				&dnsmessage.TXTResource{[]string{"Hamster Huey and the Gooey Kablooie"}},
			},
			{
				mustEDNS0ResourceHeader(4096, 0xfe0|dnsmessage.RCodeSuccess, false),
				&dnsmessage.OPTResource{
					Options: []dnsmessage.Option{
						{
							Code: 10, // see RFC 7873
							Data: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
						},
					},
				},
			},
		},
	}
}

func mustEDNS0ResourceHeader(l int, extrc dnsmessage.RCode, do bool) dnsmessage.ResourceHeader {
	h := dnsmessage.ResourceHeader{Class: dnsmessage.ClassINET}
	if err := h.SetEDNS0(l, extrc, do); err != nil {
		panic(err)
	}
	return h
}

func TestBuilder(t *testing.T) {
	msg := largeTestMsg()
	want, err := msg.Pack()
	if err != nil {
		t.Fatal("Message.Pack() =", err)
	}

	b := dnsmessage.NewBuilder(nil, msg.Header)
	b.EnableCompression()

	if err := b.StartQuestions(); err != nil {
		t.Fatal("Builder.StartQuestions() =", err)
	}
	for _, q := range msg.Questions {
		if err := b.Question(q); err != nil {
			t.Fatalf("Builder.Question(%#v) = %v", q, err)
		}
	}

	if err := b.StartAnswers(); err != nil {
		t.Fatal("Builder.StartAnswers() =", err)
	}
	for _, a := range msg.Answers {
		switch a.Header.Type {
		case dnsmessage.TypeA:
			if err := b.AResource(a.Header, *a.Body.(*dnsmessage.AResource)); err != nil {
				t.Fatalf("Builder.AResource(%#v) = %v", a, err)
			}
		case dnsmessage.TypeNS:
			if err := b.NSResource(a.Header, *a.Body.(*dnsmessage.NSResource)); err != nil {
				t.Fatalf("Builder.NSResource(%#v) = %v", a, err)
			}
		case dnsmessage.TypeCNAME:
			if err := b.CNAMEResource(a.Header, *a.Body.(*dnsmessage.CNAMEResource)); err != nil {
				t.Fatalf("Builder.CNAMEResource(%#v) = %v", a, err)
			}
		case dnsmessage.TypeSOA:
			if err := b.SOAResource(a.Header, *a.Body.(*dnsmessage.SOAResource)); err != nil {
				t.Fatalf("Builder.SOAResource(%#v) = %v", a, err)
			}
		case dnsmessage.TypePTR:
			if err := b.PTRResource(a.Header, *a.Body.(*dnsmessage.PTRResource)); err != nil {
				t.Fatalf("Builder.PTRResource(%#v) = %v", a, err)
			}
		case dnsmessage.TypeMX:
			if err := b.MXResource(a.Header, *a.Body.(*dnsmessage.MXResource)); err != nil {
				t.Fatalf("Builder.MXResource(%#v) = %v", a, err)
			}
		case dnsmessage.TypeTXT:
			if err := b.TXTResource(a.Header, *a.Body.(*dnsmessage.TXTResource)); err != nil {
				t.Fatalf("Builder.TXTResource(%#v) = %v", a, err)
			}
		case dnsmessage.TypeAAAA:
			if err := b.AAAAResource(a.Header, *a.Body.(*dnsmessage.AAAAResource)); err != nil {
				t.Fatalf("Builder.AAAAResource(%#v) = %v", a, err)
			}
		case dnsmessage.TypeSRV:
			if err := b.SRVResource(a.Header, *a.Body.(*dnsmessage.SRVResource)); err != nil {
				t.Fatalf("Builder.SRVResource(%#v) = %v", a, err)
			}
		case TypeANY:
			if err := b.UnknownResource(a.Header, *a.Body.(*dnsmessage.UnknownResource)); err != nil {
				t.Fatalf("Builder.UnknownResource(%#v) = %v", a, err)
			}
		}
	}

	if err := b.StartAuthorities(); err != nil {
		t.Fatal("Builder.StartAuthorities() =", err)
	}
	for _, a := range msg.Authorities {
		if err := b.NSResource(a.Header, *a.Body.(*dnsmessage.NSResource)); err != nil {
			t.Fatalf("Builder.NSResource(%#v) = %v", a, err)
		}
	}

	if err := b.StartAdditionals(); err != nil {
		t.Fatal("Builder.StartAdditionals() =", err)
	}
	for _, a := range msg.Additionals {
		switch a.Body.(type) {
		case *dnsmessage.TXTResource:
			if err := b.TXTResource(a.Header, *a.Body.(*dnsmessage.TXTResource)); err != nil {
				t.Fatalf("Builder.TXTResource(%#v) = %v", a, err)
			}
		case *dnsmessage.OPTResource:
			if err := b.OPTResource(a.Header, *a.Body.(*dnsmessage.OPTResource)); err != nil {
				t.Fatalf("Builder.OPTResource(%#v) = %v", a, err)
			}
		}
	}

	got, err := b.Finish()
	if err != nil {
		t.Fatal("Builder.Finish() =", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got from Builder.Finish() = %#v\nwant = %#v", got, want)
	}

	p := dnsmessage.Parser{}
	if h, err := p.Start(got); err != nil {
		t.Fatalf("parser error %v", err)
	} else {
		log.Infof("header %v", h)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatalf("p.Question() error %v", err)
	}

	log.Infof("AllAnswers %v", q)

	p.SkipAllQuestions()
	a, err := p.Answer()
	if err != nil {
		t.Fatalf("p.Answer() error %v", err)
	}

	log.Infof("Answer %v", a)

}
