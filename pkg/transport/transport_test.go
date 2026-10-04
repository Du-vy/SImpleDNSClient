package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/bootstrap"
	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/Du-vy/SImpleDNSClient/pkg/dnsmsg"
	"github.com/miekg/dns"
)

// generateTestCertificate creates an in-memory self-signed TLS cert and cert pool for testing.
func generateTestCertificate(t *testing.T, hostnames []string) (*tls.Certificate, *x509.CertPool) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SimpleDNS Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hostnames {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	certPool := x509.NewCertPool()
	parsedCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}
	certPool.AddCert(parsedCert)

	return &cert, certPool
}

func TestUDPTransportWithTCPFallback(t *testing.T) {
	// 1. Setup mock TCP server that returns complete answer
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen tcp: %v", err)
	}
	defer tcpLn.Close()

	tcpPort := tcpLn.Addr().(*net.TCPAddr).Port

	tcpServer := &dns.Server{
		Listener: tcpLn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			resp := dnsmsg.CreateResponse(r, dns.RcodeSuccess)
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("192.0.2.1").To4(),
			}
			resp.Answer = append(resp.Answer, rr)
			_ = w.WriteMsg(resp)
		}),
	}
	go func() { _ = tcpServer.ActivateAndServe() }()
	defer tcpServer.Shutdown()

	// 2. Setup mock UDP server on SAME port that returns truncated response (TC=1)
	udpPC, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", tcpPort))
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}
	defer udpPC.Close()

	udpServer := &dns.Server{
		PacketConn: udpPC,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			resp := dnsmsg.CreateTruncatedResponse(r)
			_ = w.WriteMsg(resp)
		}),
	}
	go func() { _ = udpServer.ActivateAndServe() }()
	defer udpServer.Shutdown()

	// 3. Create UDP transport with AllowTCPFallback = true
	tr, err := NewUDP(Options{
		Config: config.UpstreamConfig{
			Endpoint:         "127.0.0.1",
			Port:             tcpPort,
			Transport:        config.TransportUDP,
			AllowTCPFallback: true,
			Timeout:          2 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("failed to create udp transport: %v", err)
	}
	defer tr.Close()

	query := dnsmsg.NewQuery("fallback.test", dns.TypeA)
	resp, err := tr.Exchange(context.Background(), query)
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}

	if resp.Truncated {
		t.Errorf("expected response not to be truncated after TCP fallback")
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "192.0.2.1" {
		t.Fatalf("expected 192.0.2.1 answer from TCP fallback, got: %v", resp)
	}
}

func TestDoTTransport(t *testing.T) {
	cert, certPool := generateTestCertificate(t, []string{"localhost", "127.0.0.1"})

	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err != nil {
		t.Fatalf("failed to listen tls: %v", err)
	}
	defer tlsLn.Close()

	serverPort := tlsLn.Addr().(*net.TCPAddr).Port

	tlsServer := &dns.Server{
		Listener: tlsLn,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			resp := dnsmsg.CreateResponse(r, dns.RcodeSuccess)
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    120,
				},
				A: net.ParseIP("198.51.100.1").To4(),
			}
			resp.Answer = append(resp.Answer, rr)
			_ = w.WriteMsg(resp)
		}),
	}
	go func() { _ = tlsServer.ActivateAndServe() }()
	defer tlsServer.Shutdown()

	tr, err := NewDoT(Options{
		Config: config.UpstreamConfig{
			Endpoint:  "127.0.0.1",
			Port:      serverPort,
			Hostname:  "localhost",
			Transport: config.TransportDoT,
			Timeout:   2 * time.Second,
		},
		CustomRootCAs: certPool,
	})
	if err != nil {
		t.Fatalf("failed to create dot transport: %v", err)
	}
	defer tr.Close()

	query := dnsmsg.NewQuery("dot.test", dns.TypeA)
	resp, err := tr.Exchange(context.Background(), query)
	if err != nil {
		t.Fatalf("dot exchange failed: %v", err)
	}

	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "198.51.100.1" {
		t.Fatalf("expected 198.51.100.1 from DoT, got: %v", resp)
	}

	// Verify connection reuse by running second query
	resp2, err := tr.Exchange(context.Background(), query)
	if err != nil {
		t.Fatalf("dot second exchange failed: %v", err)
	}
	if len(resp2.Answer) != 1 {
		t.Fatalf("expected 1 answer on reused connection")
	}
}

func TestDoHTransport(t *testing.T) {
	// Create mock DoH HTTP server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad content type", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}

		reqMsg, err := dnsmsg.ParseWire(body)
		if err != nil {
			http.Error(w, "bad dns wire", http.StatusBadRequest)
			return
		}

		respMsg := dnsmsg.CreateResponse(reqMsg, dns.RcodeSuccess)
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   reqMsg.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    45,
			},
			A: net.ParseIP("203.0.113.5").To4(),
		}
		respMsg.Answer = append(respMsg.Answer, rr)

		wireResp, err := dnsmsg.PackWire(respMsg)
		if err != nil {
			http.Error(w, "pack error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wireResp)
	}))
	defer server.Close()

	// Extract port from test server
	serverURL := server.URL + "/dns-query"

	serverCertPool := x509.NewCertPool()
	serverCertPool.AddCert(server.Certificate())

	tr, err := NewDoH(Options{
		Config: config.UpstreamConfig{
			Endpoint:  serverURL,
			Transport: config.TransportDoH,
			Timeout:   2 * time.Second,
		},
		CustomRootCAs: serverCertPool,
	})
	if err != nil {
		t.Fatalf("failed to create doh transport: %v", err)
	}
	defer tr.Close()

	query := dnsmsg.NewQuery("doh.test", dns.TypeA)
	resp, err := tr.Exchange(context.Background(), query)
	if err != nil {
		t.Fatalf("doh exchange failed: %v", err)
	}

	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "203.0.113.5" {
		t.Fatalf("expected 203.0.113.5 from DoH, got: %v", resp)
	}
}

func TestTransportFactory(t *testing.T) {
	b, err := bootstrap.NewResolver(config.BootstrapConfig{
		Servers: []string{"1.1.1.1:53"},
	})
	if err != nil {
		t.Fatalf("failed to create bootstrap: %v", err)
	}

	configs := []config.UpstreamConfig{
		{Name: "udp", Transport: config.TransportUDP, Endpoint: "1.1.1.1", Port: 53},
		{Name: "tcp", Transport: config.TransportTCP, Endpoint: "1.1.1.1", Port: 53},
		{Name: "dot", Transport: config.TransportDoT, Endpoint: "1.1.1.1", Hostname: "cloudflare-dns.com", Port: 853},
		{Name: "doh", Transport: config.TransportDoH, Endpoint: "https://1.1.1.1/dns-query", Hostname: "cloudflare-dns.com"},
		{Name: "doh3", Transport: config.TransportDoH3, Endpoint: "https://1.1.1.1/dns-query", Hostname: "cloudflare-dns.com"},
		{Name: "doq", Transport: config.TransportDoQ, Endpoint: "1.1.1.1", Hostname: "cloudflare-dns.com", Port: 853},
	}

	for _, cfg := range configs {
		tr, err := NewTransport(Options{
			Config:    cfg,
			Bootstrap: b,
		})
		if err != nil {
			t.Errorf("failed to create transport for %s: %v", cfg.Transport, err)
			continue
		}
		if tr.Protocol() != cfg.Transport {
			t.Errorf("protocol mismatch: %s vs %s", tr.Protocol(), cfg.Transport)
		}
		_ = tr.Close()
	}
}
