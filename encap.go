package erspan

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"syscall"
	"github.com/google/gopacket"
)

type ErspanEncap struct {
	fd		int
	DestIp	net.IP
	Key		uint32
	SeqNum	uint32
}

func NewErspanEncap(destIp string, key uint32, startSeqNum uint32) *ErspanEncap {
	ip := net.ParseIP(destIp)
	if ip == nil {
		log.Printf("Error: Incorrect IP address passed to Connect %s\n", destIp)
	}
	encap := ErspanEncap{
		DestIp:		ip,
		Key:		key,
		SeqNum:		startSeqNum,
	}
	return &encap
}

func (encap *ErspanEncap) Connect() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_GRE)
	if err != nil {
		log.Printf("Failed to open socket to send GRE traffic %s\n", err)
		return err
	}
	encap.fd = fd
	return nil
}

func (encap *ErspanEncap) Send(ci gopacket.CaptureInfo, packet []byte) error {

	// prepend the GRE + Erspan headers
	addr :=  syscall.SockaddrInet4{
		Port: 0,
	}
	copy(addr.Addr[:], encap.DestIp.To4())
	p, err := encap.Encapsulate(packet)
	if err != nil {
		return err
	}
	ci.CaptureLength = len(p)
	ci.Length = len(p)
	err = syscall.Sendto(encap.fd, p, 0, &addr)
	if err != nil {
		log.Fatal("Sendto:", err)
	}
	return err
}

func (encap *ErspanEncap) Encapsulate(packet []byte) ([]byte, error) {
	gre := GREHeader{
		Flags: 0x1,
		Protocol: 0x88be, //ERSPAN Type II
		SequenceNumber:	encap.SeqNum,
	}
	encap.SeqNum += 1

	greBytes, err := gre.Marshal()
	if err != nil {
		return nil, err
	}
	fmt.Printf("GRE Header(%d): %s\n", len(greBytes), hex.EncodeToString(greBytes))
	erspan := ErspanHeader{
		Version:		1,
		Vlan:			0,
		Cos:			0,
		En:				0,
		Truncated:		0,
		SessionId:		64,
		Index:			1,
	}

	erspanBytes, err := erspan.Marshal()
	if err != nil {
		return nil, err
	}
	fmt.Printf("GRE Header(%d): %s\n", len(greBytes), hex.EncodeToString(greBytes))
	headers := append(greBytes, erspanBytes...)
	return append(headers, packet...), nil
}
