package erspan

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

type ErspanHeaderFlags int

type ErspanHeader struct {
	Version			uint16
	Vlan			uint16
	Cos				uint8
	En				uint8
	Truncated		uint8
	SessionId		uint16
	Index			uint32
}

func (h *ErspanHeader) String() string {
	if h == nil {
		return "<nil>"
	}
	return fmt.Sprintf("Version=%d Vlan=%d, En=%d SessionId=%d, Index=%d", h.Version, h.Vlan, h.En, h.SessionId, h.Index)
}

func ParseErspanHeader(b []byte) (*ErspanHeader, error) {
	h := &ErspanHeader{
		Version:	uint16(b[0] >> 4),
		Index:	uint32(binary.BigEndian.Uint32(b[4:8])),
	}
	h.Vlan = uint16(uint16(b[1]) | (uint16)(b[0] & 0xf) << 8)

	flagsAndSessionId := uint16(binary.BigEndian.Uint16(b[2:4]))
	h.SessionId = flagsAndSessionId & 0x2ff
	flags := (flagsAndSessionId >> 10)
	h.Cos = uint8((flags >> 3) & 0x7)
	h.En = uint8((flags >> 1) & 0x3)
	h.Truncated = uint8(flags & 0x1)
	return h, nil
}

func (h *ErspanHeader) Marshal() ([]byte, error) {
	if h == nil {
		return nil, syscall.EINVAL
	}
	hdrLen := 8
	b := make([]byte, hdrLen)
	b[0] = byte(h.Version << 4 | (h.Vlan >> 8) & 0x0f)
	b[1] = byte(h.Vlan & 0x00ff)

	flags := ((h.Cos & 0x7) << 3| (h.En & 0x3) << 1 | h.Truncated)
	flagsAndSessionId := (h.SessionId & 0x2ff) | uint16(flags << 10)
	binary.BigEndian.PutUint16(b[2:4], uint16(flagsAndSessionId))
	binary.BigEndian.PutUint32(b[4:8], uint32(h.Index & 0xfffff))
	return b, nil
}
