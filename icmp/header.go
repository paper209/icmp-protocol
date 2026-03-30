package icmp

import (
	"encoding/binary"
	"errors"
	"study/util"
)

// total bytes = 4
type Header struct {
	Type     uint8  // 1
	Code     uint8  // 1
	Checksum uint16 // 2
}

func (h *Header) buildHeader(buf []byte) {
	buf[0] = h.Type
	buf[1] = h.Code
	binary.BigEndian.PutUint16(buf[2:4], 0)
}

func decodeHeader(buf []byte) (*Header, error) {
	if len(buf) < 24 {
		return nil, errors.New("invalid length")
	} else if util.Checksum(buf[20:]) != 0 {
		return nil, errors.New("invalid checksum")
	}

	return &Header{
		Type:     buf[20],
		Code:     buf[21],
		Checksum: binary.BigEndian.Uint16(buf[22:24]),
	}, nil
}
