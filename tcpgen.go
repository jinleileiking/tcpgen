package tcpgen

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	magicNumber  = 0xa1b23c4d // nanosecond resolution
	versionMajor = 2
	versionMinor = 4
	snapLen      = 65535
	linkType     = 101 // LINKTYPE_RAW http://www.tcpdump.org/linktypes.html

)

type header struct {
	// MagicNumber: used to detect the file format itself and the byte ordering.
	// The writing application writes 0xa1b2c3d4 with it's native byte ordering
	// format into this field. The reading application will read either 0xa1b2c3d4
	// (identical) or 0xd4c3b2a1 (swapped). If the reading application reads the
	// swapped 0xd4c3b2a1 value, it knows that all the following fields will have
	// to be swapped too. For nanosecond-resolution files, the writing application
	// writes 0xa1b23c4d, with the two nibbles of the two lower-order bytes swapped,
	// and the reading application will read either 0xa1b23c4d (identical)
	// or 0x4d3cb2a1 (swapped).
	// total 4 + 2 + 2+ 4 + 4 + 4 + 4 = 16 + 8  = 24 bytes
	MagicNumber uint32
	// VersionMajor, VersionMinor: the version number of this file format (current version is 2.4)
	VersionMajor, VersionMinor uint16
	// ThisZone: the correction time in seconds between GMT (UTC) and the local
	// timezone of the following packet header timestamps. Examples: If the
	// timestamps are in GMT (UTC), thiszone is simply 0. If the timestamps are
	// in Central European time (Amsterdam, Berlin, ...) which is GMT + 1:00,
	// thiszone must be -3600. In practice, time stamps are always in GMT, so
	// ThisZone is always 0.
	ThisZone int32
	// SigFigs: in theory, the accuracy of time stamps in the capture; in practice,
	// all tools set it to 0
	SigFigs uint32
	// SnapLen: the "snapshot length" for the capture (typically 65535 or even more,
	// but might be limited by the user), see: InclLen vs. OrigLen below
	SnapLen uint32
	// Network: link-layer header type, specifying the type of headers at the
	// beginning of the packet (e.g. 1 for Ethernet, see tcpdump.org's link-layer
	// header types page for details); this can be various types such as 802.11,
	// 802.11 with various radio information, PPP, Token Ring, FDDI, etc.
	Network uint32
}

type packetHeader struct {
	// TsSec: the date and time when this packet was captured. This value is in
	// seconds since January 1, 1970 00:00:00 GMT; this is also known as a UN*X
	// time_t. You can use the ANSI C time() function from time.h to get this
	// value, but you might use a more optimized way to get this timestamp value.
	// If this timestamp isn't based on GMT (UTC), use thiszone from the global
	// header for adjustments.
	TsSec uint32
	// TsUsec: in regular pcap files, the microseconds when this packet was
	// captured, as an offset to TsSec. In nanosecond-resolution files, this is,
	// instead, the nanoseconds when the packet was captured, as an offset to
	// TsSec /!\ Beware: this value shouldn't reach 1 second (in regular pcap
	// files 1 000 000; in nanosecond-resolution files, 1 000 000 000); in this
	// case TsSec must be increased instead!
	TsUsec uint32
	// InclLen: the number of bytes of packet data actually captured and saved
	// in the file. This value should never become larger than OrigLen or the
	// snaplen value of the global header.
	InclLen uint32
	// OrigLen: the length of the packet as it appeared on the network when it
	// was captured. If InclLen and OrigLen differ, the actually saved packet
	// size was limited by snaplen.
	OrigLen uint32
}

type Writer struct {
	writer io.Writer

	src net.IP
	dst net.IP
}

func NewWriter(w io.Writer) (*Writer, error) {
	//TODO: overwrite default
	pw := &Writer{
		writer: w,
		src:    []byte{10, 0, 0, 0},
		dst:    []byte{10, 1, 1, 1},
	}

	if err := pw.writeHeader(); err != nil {
		return nil, err
	}

	return pw, nil
}

func (w *Writer) writeHeader() error {
	h := header{
		MagicNumber:  magicNumber,
		VersionMajor: versionMajor,
		VersionMinor: versionMinor,
		ThisZone:     0,
		SigFigs:      0,
		SnapLen:      snapLen,
		Network:      linkType,
	}

	if err := binary.Write(w.writer, binary.BigEndian, h); err != nil {
		return err
	}

	return nil
}

func timestamp(t time.Time) (secs, nanos uint32) {
	ns := t.UnixNano()
	secs = uint32(ns / int64(time.Second))
	nanos = uint32(ns % int64(time.Second))
	return secs, nanos
}

func (w *Writer) writeTCP(payload []byte) error {
	var payloadTCP []byte
	var err error
	if payloadTCP, err = w.genTCPPayload(payload); err != nil {
		return err
	}

	secs, nanos := timestamp(time.Now())
	hdr := packetHeader{
		TsSec:   secs,
		TsUsec:  nanos,
		InclLen: uint32(len(payloadTCP)),
		OrigLen: uint32(len(payloadTCP)),
	}

	if err := binary.Write(w.writer, binary.BigEndian, hdr); err != nil {
		return err
	}

	spew.Dump(payloadTCP)
	if _, err := w.writer.Write(payloadTCP); err != nil {
		return err
	}
	return nil
}

func (w *Writer) genTCPPayload(payload []byte) ([]byte, error) {
	options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	// ethernetLayer := &layers.Ethernet{
	// 	SrcMAC: net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
	// 	DstMAC: net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
	// }
	ipLayer := &layers.IPv4{
		Version:  4,
		SrcIP:    net.IP{127, 0, 0, 1},
		DstIP:    net.IP{8, 8, 8, 8},
		Length:   20,
		IHL:      5,
		Protocol: layers.IPProtocolTCP,
		TTL:      8,
		Flags:    0,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(4444),
		DstPort: layers.TCPPort(1935),
	}
	tcpLayer.Payload = payload
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	bTCP := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(bTCP, options,
		tcpLayer,
		gopacket.Payload(payload),
	); err != nil {
		return nil, err
	}
	ipLayer.Payload = bTCP.Bytes()
	spew.Dump(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, options,
		// ethernetLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(payload),
	); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
