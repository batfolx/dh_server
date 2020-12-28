package tcp_server

import (
	"fmt"
	"math/big"
	"net"
)

type EncryptedTunnel struct {
	Conn     *net.Conn
	Key      *big.Int
	KeyBytes [32]byte
}

type TunnelErr struct {
	err string
}

func (t *TunnelErr) Error() string {
	return (t).err
}

func NewEncryptedTunnel() *EncryptedTunnel {
	return &EncryptedTunnel{
		Conn:     nil,
		Key:      nil,
		KeyBytes: *new([32]byte),
	}
}

func printErr(err error) {
	fmt.Printf("Error %v\n", err)
}
