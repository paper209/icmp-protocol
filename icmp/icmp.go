package icmp

import (
	"fmt"
	"syscall"
)

func Read(s int) ([]byte, error) {
	buf := make([]byte, 1500)
	n, _, err := syscall.Recvfrom(s, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("socket error: %w", err)
	}
	return buf[:n], nil
}
