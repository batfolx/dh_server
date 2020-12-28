package tcp_server

import (
	"fmt"
	"math/big"
	"net"
)

type EncryptedTunnel struct {

	Conn *net.Conn
	Key *big.Int
	KeyBytes []byte


}


type TunnelErr struct {
	err string
}

func (t *TunnelErr) Error() string {
	return (t).err
}

func NewEncryptedTunnel() *EncryptedTunnel {
	return &EncryptedTunnel{
		Conn: nil,
		Key:  nil,
		KeyBytes: nil,
	}
}

func printErr(err error) {
	fmt.Printf("Error %v\n", err)
}

