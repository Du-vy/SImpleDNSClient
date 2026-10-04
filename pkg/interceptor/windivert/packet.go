package windivert

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	ProtocolTCP = 6
	ProtocolUDP = 17

	IPv4MinHeaderLen = 20
	IPv6HeaderLen    = 40
	UDPHeaderLen     = 8
	TCPMinHeaderLen  = 20
)

var (
	ErrPacketTooShort     = errors.New("packet buffer too short")
	ErrUnsupportedIPVer   = errors.New("unsupported IP version")
	ErrNonDNSPacket       = errors.New("packet is not port 53 DNS")
	ErrInvalidHeaderLen   = errors.New("invalid IP header length")
)

// ParsedPacket represents a dissected IP/UDP/TCP packet.
type ParsedPacket struct {
	IsIPv6     bool
	Protocol   uint8
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	IPHdrLen   int
	Payload    []byte // Transport payload (DNS wire query)
	RawData    []byte // Full raw packet data
}

// ParsePacket dissects a raw IP packet into a ParsedPacket.
func ParsePacket(data []byte) (*ParsedPacket, error) {
	if len(data) < IPv4MinHeaderLen {
		return nil, ErrPacketTooShort
	}

	version := data[0] >> 4
	p := &ParsedPacket{
		RawData: data,
	}

	var proto uint8
	var ipHdrLen int
	var srcIP, dstIP net.IP

	switch version {
	case 4:
		p.IsIPv6 = false
		ihl := int(data[0] & 0x0F)
		ipHdrLen = ihl * 4
		if ipHdrLen < IPv4MinHeaderLen || len(data) < ipHdrLen {
			return nil, ErrInvalidHeaderLen
		}
		proto = data[9]
		srcIP = net.IP(data[12:16])
		dstIP = net.IP(data[16:20])

	case 6:
		p.IsIPv6 = true
		ipHdrLen = IPv6HeaderLen
		if len(data) < ipHdrLen {
			return nil, ErrPacketTooShort
		}
		proto = data[6] // Next Header
		srcIP = net.IP(data[8:24])
		dstIP = net.IP(data[24:40])

	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedIPVer, version)
	}

	p.Protocol = proto
	p.IPHdrLen = ipHdrLen
	p.SrcIP = srcIP
	p.DstIP = dstIP

	transportData := data[ipHdrLen:]

	switch proto {
	case ProtocolUDP:
		if len(transportData) < UDPHeaderLen {
			return nil, ErrPacketTooShort
		}
		p.SrcPort = binary.BigEndian.Uint16(transportData[0:2])
		p.DstPort = binary.BigEndian.Uint16(transportData[2:4])
		udpLen := int(binary.BigEndian.Uint16(transportData[4:6]))
		if udpLen < UDPHeaderLen || len(transportData) < udpLen {
			return nil, ErrPacketTooShort
		}
		p.Payload = transportData[UDPHeaderLen:udpLen]

	case ProtocolTCP:
		if len(transportData) < TCPMinHeaderLen {
			return nil, ErrPacketTooShort
		}
		p.SrcPort = binary.BigEndian.Uint16(transportData[0:2])
		p.DstPort = binary.BigEndian.Uint16(transportData[2:4])
		dataOffset := int(transportData[12]>>4) * 4
		if len(transportData) >= dataOffset {
			p.Payload = transportData[dataOffset:]
		}

	default:
		return nil, fmt.Errorf("unsupported transport protocol %d", proto)
	}

	return p, nil
}

// BuildUDPResponsePacket constructs a reversed inbound IP/UDP response packet with the new DNS payload.
// Source IP/Port and Destination IP/Port are swapped, and checksums are computed.
func BuildUDPResponsePacket(orig *ParsedPacket, dnsResponsePayload []byte) ([]byte, error) {
	if orig.Protocol != ProtocolUDP {
		return nil, fmt.Errorf("cannot build UDP response for non-UDP packet")
	}

	newUDPLen := UDPHeaderLen + len(dnsResponsePayload)

	if !orig.IsIPv6 {
		// IPv4 packet
		ipHdrLen := IPv4MinHeaderLen
		totalLen := ipHdrLen + newUDPLen
		buf := make([]byte, totalLen)

		// Copy original IPv4 header
		copy(buf[:ipHdrLen], orig.RawData[:ipHdrLen])

		// Reset header length and IHL in case options were present
		buf[0] = 0x45 // Version 4, IHL 5 (20 bytes)
		buf[1] = 0x00 // DSCP/ECN
		binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
		binary.BigEndian.PutUint16(buf[4:6], 0) // ID
		binary.BigEndian.PutUint16(buf[6:8], 0x4000) // Don't Fragment flag
		buf[8] = 64 // TTL
		buf[9] = ProtocolUDP

		// Clear IP checksum field before computation
		buf[10] = 0
		buf[11] = 0

		// Swap IPs: Response Src = Orig Dst, Response Dst = Orig Src
		copy(buf[12:16], orig.DstIP.To4())
		copy(buf[16:20], orig.SrcIP.To4())

		// Compute IPv4 header checksum
		ipChecksum := computeChecksum(buf[:ipHdrLen])
		binary.BigEndian.PutUint16(buf[10:12], ipChecksum)

		// UDP Header
		udpBuf := buf[ipHdrLen:]
		binary.BigEndian.PutUint16(udpBuf[0:2], orig.DstPort) // Src Port = Orig Dst Port (53)
		binary.BigEndian.PutUint16(udpBuf[2:4], orig.SrcPort) // Dst Port = Orig Src Port
		binary.BigEndian.PutUint16(udpBuf[4:6], uint16(newUDPLen))
		udpBuf[6] = 0 // Checksum placeholder
		udpBuf[7] = 0

		// Copy DNS Response payload
		copy(udpBuf[UDPHeaderLen:], dnsResponsePayload)

		// Compute UDP Checksum with IPv4 pseudo-header
		udpChecksum := computeUDPChecksumV4(orig.DstIP.To4(), orig.SrcIP.To4(), udpBuf)
		if udpChecksum == 0 {
			udpChecksum = 0xFFFF
		}
		binary.BigEndian.PutUint16(udpBuf[6:8], udpChecksum)

		return buf, nil
	}

	// IPv6 packet
	ipHdrLen := IPv6HeaderLen
	totalLen := ipHdrLen + newUDPLen
	buf := make([]byte, totalLen)

	// Copy base IPv6 header
	copy(buf[:ipHdrLen], orig.RawData[:ipHdrLen])
	buf[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(buf[4:6], uint16(newUDPLen)) // Payload length
	buf[6] = ProtocolUDP // Next header
	buf[7] = 64 // Hop Limit

	// Swap IPs: Response Src = Orig Dst, Response Dst = Orig Src
	copy(buf[8:24], orig.DstIP.To16())
	copy(buf[24:40], orig.SrcIP.To16())

	// UDP Header
	udpBuf := buf[ipHdrLen:]
	binary.BigEndian.PutUint16(udpBuf[0:2], orig.DstPort)
	binary.BigEndian.PutUint16(udpBuf[2:4], orig.SrcPort)
	binary.BigEndian.PutUint16(udpBuf[4:6], uint16(newUDPLen))
	udpBuf[6] = 0
	udpBuf[7] = 0

	// Copy DNS Response payload
	copy(udpBuf[UDPHeaderLen:], dnsResponsePayload)

	// Compute UDP Checksum with IPv6 pseudo-header (mandatory in IPv6)
	udpChecksum := computeUDPChecksumV6(orig.DstIP.To16(), orig.SrcIP.To16(), udpBuf)
	if udpChecksum == 0 {
		udpChecksum = 0xFFFF
	}
	binary.BigEndian.PutUint16(udpBuf[6:8], udpChecksum)

	return buf, nil
}

// computeChecksum calculates the standard RFC 1071 16-bit one's complement checksum.
func computeChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)

	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}

	return ^uint16(sum)
}

// computeUDPChecksumV4 calculates the UDP checksum including the IPv4 pseudo-header.
func computeUDPChecksumV4(srcIP, dstIP net.IP, udpPacket []byte) uint16 {
	var sum uint32

	// Pseudo-header: Src IP (4 bytes), Dst IP (4 bytes), Zero + Proto (2 bytes), UDP Len (2 bytes)
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	sum += uint32(ProtocolUDP)
	sum += uint32(len(udpPacket))

	// UDP packet (Header + Data)
	length := len(udpPacket)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpPacket[i : i+2]))
	}
	if length%2 == 1 {
		sum += uint32(udpPacket[length-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}

	return ^uint16(sum)
}

// computeUDPChecksumV6 calculates the UDP checksum including the IPv6 pseudo-header.
func computeUDPChecksumV6(srcIP, dstIP net.IP, udpPacket []byte) uint16 {
	var sum uint32

	// IPv6 Pseudo-header: Src IP (16 bytes), Dst IP (16 bytes), UDP Length (4 bytes), Next Header (4 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(srcIP[i : i+2]))
		sum += uint32(binary.BigEndian.Uint16(dstIP[i : i+2]))
	}
	sum += uint32(len(udpPacket))
	sum += uint32(ProtocolUDP)

	// UDP packet
	length := len(udpPacket)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpPacket[i : i+2]))
	}
	if length%2 == 1 {
		sum += uint32(udpPacket[length-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}

	return ^uint16(sum)
}
