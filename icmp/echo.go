package icmp

import (
	"encoding/binary"
	"errors"
	"study/util"
)

// total bytes = 4
type Echo struct {
	Identifier uint16
	Sequence   uint16
	Data       []byte
}

func decodeEcho(buf []byte) (*Echo, error) {
	if len(buf) < 28 {
		return nil, errors.New("invalid length")
	}

	return &Echo{
		Identifier: binary.BigEndian.Uint16(buf[24:26]),
		Sequence:   binary.BigEndian.Uint16(buf[26:28]),
		Data:       buf[28:],
	}, nil
}

func (e *Echo) buildEchoRequest() []byte {
	buf := make([]byte, 8+len(e.Data))

	h := &Header{
		Type:     8,
		Code:     0,
		Checksum: 0,
	}
	h.buildHeader(buf)

	binary.BigEndian.PutUint16(buf[4:6], e.Identifier)
	binary.BigEndian.PutUint16(buf[6:8], e.Sequence)
	copy(buf[8:], e.Data)
	binary.BigEndian.PutUint16(buf[2:4], util.Checksum(buf))

	return buf
}
