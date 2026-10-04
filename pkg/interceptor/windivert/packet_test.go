package windivert

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/Du-vy/SImpleDNSClient/pkg/dnsmsg"
	"github.com/miekg/dns"
)

// createRawIPv4UDPPacket creates an IPv4 UDP packet in memory for testing.
func createRawIPv4UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	ipHdrLen := 20
	udpLen := 8 + len(payload)
	totalLen := ipHdrLen + udpLen

	buf := make([]byte, totalLen)
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	buf[8] = 64
	buf[9] = ProtocolUDP
	copy(buf[12:16], srcIP.To4())
	copy(buf[16:20], dstIP.To4())

	ipCheck := computeChecksum(buf[:ipHdrLen])
	binary.BigEndian.PutUint16(buf[10:12], ipCheck)

	udpBuf := buf[ipHdrLen:]
	binary.BigEndian.PutUint16(udpBuf[0:2], srcPort)
	binary.BigEndian.PutUint16(udpBuf[2:4], dstPort)
	binary.BigEndian.PutUint16(udpBuf[4:6], uint16(udpLen))
	copy(udpBuf[8:], payload)

	udpCheck := computeUDPChecksumV4(srcIP.To4(), dstIP.To4(), udpBuf)
	binary.BigEndian.PutUint16(udpBuf[6:8], udpCheck)

	return buf
}

func TestParseIPv4Packet(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("8.8.8.8")
	srcPort := uint16(54321)
	dstPort := uint16(53)

	q := dnsmsg.NewQuery("example.com", dns.TypeA)
	wire, err := dnsmsg.PackWire(q)
	if err != nil {
		t.Fatalf("failed to pack dns wire: %v", err)
	}

	raw := createRawIPv4UDPPacket(srcIP, dstIP, srcPort, dstPort, wire)

	parsed, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("failed to parse raw IPv4 packet: %v", err)
	}

	if parsed.IsIPv6 {
		t.Errorf("expected IPv4, got IPv6")
	}
	if !parsed.SrcIP.Equal(srcIP) {
		t.Errorf("expected src IP %s, got %s", srcIP, parsed.SrcIP)
	}
	if !parsed.DstIP.Equal(dstIP) {
		t.Errorf("expected dst IP %s, got %s", dstIP, parsed.DstIP)
	}
	if parsed.SrcPort != srcPort || parsed.DstPort != dstPort {
		t.Errorf("port mismatch: %d -> %d", parsed.SrcPort, parsed.DstPort)
	}
	if len(parsed.Payload) != len(wire) {
		t.Errorf("payload length mismatch: %d vs %d", len(parsed.Payload), len(wire))
	}
}

func TestBuildUDPResponsePacketV4(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.50")
	dstIP := net.ParseIP("1.1.1.1")
	srcPort := uint16(49152)
	dstPort := uint16(53)

	req := dnsmsg.NewQuery("test.org", dns.TypeA)
	reqWire, _ := dnsmsg.PackWire(req)

	rawReq := createRawIPv4UDPPacket(srcIP, dstIP, srcPort, dstPort, reqWire)
	parsedReq, err := ParsePacket(rawReq)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Create response DNS msg
	respMsg := dnsmsg.CreateResponse(req, dns.RcodeSuccess)
	respWire, _ := dnsmsg.PackWire(respMsg)

	respPacketBytes, err := BuildUDPResponsePacket(parsedReq, respWire)
	if err != nil {
		t.Fatalf("failed to build UDP response packet: %v", err)
	}

	// Parse the built response packet
	parsedResp, err := ParsePacket(respPacketBytes)
	if err != nil {
		t.Fatalf("failed to parse built response packet: %v", err)
	}

	// Verify reversed IPs and ports
	if !parsedResp.SrcIP.Equal(dstIP) {
		t.Errorf("expected response SrcIP to be %s, got %s", dstIP, parsedResp.SrcIP)
	}
	if !parsedResp.DstIP.Equal(srcIP) {
		t.Errorf("expected response DstIP to be %s, got %s", srcIP, parsedResp.DstIP)
	}
	if parsedResp.SrcPort != 53 {
		t.Errorf("expected response SrcPort to be 53, got %d", parsedResp.SrcPort)
	}
	if parsedResp.DstPort != srcPort {
		t.Errorf("expected response DstPort to be %d, got %d", srcPort, parsedResp.DstPort)
	}

	// Verify IPv4 header checksum
	hdrCheck := computeChecksum(respPacketBytes[:20])
	if hdrCheck != 0 {
		t.Errorf("IPv4 header checksum validation failed (expected 0, got 0x%04X)", hdrCheck)
	}
}

func TestPacketTooShort(t *testing.T) {
	_, err := ParsePacket([]byte{0x45, 0x00})
	if err != ErrPacketTooShort {
		t.Errorf("expected ErrPacketTooShort, got %v", err)
	}
}

func BenchmarkParsePacket(b *testing.B) {
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("8.8.8.8")
	q := dnsmsg.NewQuery("bench.com", dns.TypeA)
	wire, _ := dnsmsg.PackWire(q)
	raw := createRawIPv4UDPPacket(srcIP, dstIP, 54321, 53, wire)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParsePacket(raw)
	}
}

func BenchmarkBuildUDPResponsePacket(b *testing.B) {
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("8.8.8.8")
	q := dnsmsg.NewQuery("bench.com", dns.TypeA)
	wire, _ := dnsmsg.PackWire(q)
	raw := createRawIPv4UDPPacket(srcIP, dstIP, 54321, 53, wire)
	parsed, _ := ParsePacket(raw)

	resp := dnsmsg.CreateResponse(q, dns.RcodeSuccess)
	respWire, _ := dnsmsg.PackWire(resp)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = BuildUDPResponsePacket(parsed, respWire)
	}
}
