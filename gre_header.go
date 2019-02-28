package erspan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
)

type GREHeaderFlags int

type GREHeader struct {
	Flags			GREHeaderFlags
	Protocol		uint16
	Checksum		uint32
	Key				uint32
	SequenceNumber	uint32
}

func (h *GREHeader) String() string {
	if h == nil {
		return "<nil>"
	}
	return fmt.Sprintf("flags=%d protocol=%d", h.Flags, h.Protocol)
}

func ParseGREHeader(b []byte) (*GREHeader, error) {
	h := &GREHeader{
		Flags:		GREHeaderFlags(b[0] >> 4),
		Protocol:	uint16(binary.BigEndian.Uint16(b[2:4])),
	}
	nextOffset := 4
	if h.Flags & (0x1 << 3) != 0 {
		//checksum present
		if len(b) < nextOffset  + 4 {
			return nil, errors.New("Size too small to hold checksum")
		}
		h.Checksum = uint32(binary.BigEndian.Uint16(b[4:6]))
		nextOffset += 4
	}
	if (h.Flags & (0x1 << 1)) != 0 {
		if len(b) < nextOffset  + 4 {
			return nil, errors.New("Size too small to hold Key")
		}
		h.Key = uint32(binary.BigEndian.Uint32(b[nextOffset: nextOffset+4]))
		nextOffset += 4
	}
	if h.Flags & 0x1  != 0 {
		if len(b) < nextOffset  + 4 {
			return nil, errors.New("Size too small to hold Sequence Number")
		}
		h.SequenceNumber = uint32(binary.BigEndian.Uint32(b[nextOffset: nextOffset+4]))
		nextOffset += 4
	}
	return h, nil
}

func (h *GREHeader) Marshal() ([]byte, error) {
	nextOffset := 0
	if h == nil {
		return nil, syscall.EINVAL
	}
	h.Flags = 0
	hdrLen := 4
	if h.Key != 0 {
		hdrLen += 4
		h.Flags |= 0x1 << 1
	}
	if h.Checksum != 0 {
		hdrLen += 4
		h.Flags |= 0x1 << 3
	}
	if h.SequenceNumber != 0 {
		hdrLen += 4
		h.Flags |= 0x1
	}

	b := make([]byte, hdrLen)
	b[0] = byte(h.Flags << 4| 0 & 0x0f)
	b[1] = byte(0)
	binary.BigEndian.PutUint16(b[2:4], uint16(h.Protocol))
	nextOffset = 4
	if h.Checksum != 0 {
		binary.BigEndian.PutUint16(b[4:6], uint16(h.Checksum))
		binary.BigEndian.PutUint16(b[6:8], uint16(0))
		nextOffset += 4
	}
	if h.Key != 0{
		binary.BigEndian.PutUint32(b[nextOffset:nextOffset + 4], h.Key)
		nextOffset += 4
	}
	if h.SequenceNumber != 0 {
		binary.BigEndian.PutUint32(b[nextOffset:nextOffset + 4], h.SequenceNumber)
		nextOffset += 4
	}
	return b, nil
}
