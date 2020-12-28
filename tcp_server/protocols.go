package tcp_server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
)


func readPrimeNumber(conn *net.Conn) (*big.Int, error) {
	// reads a prime number from the client
	// for the purposes of Diffe - Hellman key exchange
	primeNumber := new(big.Int)
	tunnelErr := TunnelErr{err: ""}

	// get the size of the prime
	primeSizeBuf := make([]byte, 4)
	n, err := (*conn).Read(primeSizeBuf)


	if err != nil {
		fmt.Printf("Error %v\n", err)
		return primeNumber, err
	}

	if n != len(primeSizeBuf) {
		fmt.Printf("Failed to read %d bytes - only read %d bytes in prime size buf\n", len(primeSizeBuf), n)
		tunnelErr.err = "Mismatched bytes sent."
		return primeNumber, &tunnelErr
	}

	// convert the 4 bytes to a uint32 which is length of incoming prime number
	primeSize := binary.BigEndian.Uint32(primeSizeBuf)

	fmt.Printf("Incoming prime size %d\n", primeSize)

	// create another buffer
	primeBuf := make([]byte, primeSize)

	n, err = (*conn).Read(primeBuf)

	if err != nil {
		printErr(err)
		return primeNumber, err
	}

	if n != len(primeBuf) {
		fmt.Printf("Failed to read %d bytes - only read %d bytes in prime buf\n", len(primeBuf), n)
		tunnelErr.err = "Mismatched bytes sent."
		return primeNumber, &tunnelErr
	}

	primeNumber = primeNumber.SetBytes(primeBuf)
	return primeNumber, nil

}

func readGenerator(conn *net.Conn) (*big.Int, error) {

	t := TunnelErr{err: ""}
	generator := new(big.Int)
	genSzBuf := make([]byte, 4)

	n, err := (*conn).Read(genSzBuf)
	if err != nil {
		printErr(err)
		return generator, err
	}

	if n != len(genSzBuf) {
		t.err = fmt.Sprintf("Mismatched bytes. %d sent, %d actually needed to be sent.\n", n, len(genSzBuf))
		return generator, &t
	}

	// convert generator buffer to size
	genSz := binary.BigEndian.Uint32(genSzBuf)

	fmt.Printf("Incoming generator size %d\n", genSz)

	// make another buffer to store the generator
	generatorBuf := make([]byte, genSz)

	n, err = (*conn).Read(generatorBuf)
	if err != nil {
		printErr(err)
		return generator, err
	}

	if n != len(generatorBuf) {
		t.err = fmt.Sprintf("Mismatched bytes. %d sent, %d actually needed to be sent.\n", n, len(genSzBuf))
		return generator, &t
	}

	generator.SetBytes(generatorBuf)

	return generator, nil

}

func readPublicKey(conn *net.Conn) (*big.Int, error){

	clientKey := new(big.Int)
	t := TunnelErr{err: ""}
	pubkeySz := make([]byte, 4)

	n, err := (*conn).Read(pubkeySz)
	if err != nil {
		printErr(err)
		return clientKey, err
	}

	if n != len(pubkeySz) {
		t.err = fmt.Sprintf("Mismatch bytes. Got %d, meant to get %d\n", n, len(pubkeySz))
		return clientKey, &t
	}

	pubkey := binary.BigEndian.Uint32(pubkeySz)
	fmt.Printf("Got public key size %v\n", pubkeySz)

	clientKeyBuf := make([]byte, pubkey)

	n, err = (*conn).Read(clientKeyBuf)
	if err != nil {
		printErr(err)
		return clientKey, err
	}

	if n != len(clientKeyBuf) {
		t.err = fmt.Sprintf("Mismatch bytes. Got %d, meant to get %d\n", n, len(clientKeyBuf))
		return clientKey, &t
	}

	clientKey.SetBytes(clientKeyBuf)


	return clientKey, nil

}

func generateServerSecret(prime *big.Int) (*big.Int, error) {
	return rand.Int(rand.Reader, prime)
}

func sendServerPublicKey(prime *big.Int, generator *big.Int, serverSecret *big.Int, conn *net.Conn) {

	result := new(big.Int)
	result.Exp(generator, serverSecret, prime)

	// 4 bytes for the length of the result
	resultBuffer := make([]byte, 4)
	binary.BigEndian.PutUint32(resultBuffer, uint32(len(result.Bytes())))

	resultBuffer = append(resultBuffer, result.Bytes()...)

	n, err := (*conn).Write(resultBuffer)
	if err != nil {
		printErr(err)
		return
	}

	if n != len(resultBuffer) {

		fmt.Printf("Mismatched bytes %d sent %d actual\n", n, len(resultBuffer))
		return
	}

	fmt.Printf("Sent this server key %v\n", result.Bytes())


}

func generateSessionKey(clientKey *big.Int, serverSecret *big.Int, prime *big.Int) *big.Int {

	return new(big.Int).Exp(clientKey, serverSecret, prime)

}


func EncryptMessage(tunnel *EncryptedTunnel, message string) ([]byte, error) {

	var encryptedBytes []byte
	c, err := aes.NewCipher(tunnel.KeyBytes)
	if err != nil {
		printErr(err)
		return encryptedBytes, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return encryptedBytes, err
	}

	// fill nonce with random garbage
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
		return encryptedBytes, err
	}

	// encrypt the message to send to client
	encryptedBytes = gcm.Seal(nonce, nonce, []byte(message), nil)

	return encryptedBytes, nil



}