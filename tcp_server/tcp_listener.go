package tcp_server

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"time"
)

func SetupListener() {

	addr := "127.0.0.1:9000"

	var listener net.Listener = nil

	for {
		_listener, err := net.Listen("tcp", addr)
		if err != nil {
			fmt.Printf("Error in spinning up listener... trying again %v\n", err)
			time.Sleep(5 * time.Second)
		} else {
			listener = _listener
			break
		}

	}

	for {

		conn, err := listener.Accept()
		if err != nil {
			continue
		} else {
			go handleConnection(&conn)
		}

	}

}

func handleConnection(conn *net.Conn) {

	tunnel, err := setupEncryptedTunnel(conn)
	if err != nil {
		printErr(err)
		return
	}

	reader := bufio.NewReader(os.Stdin)
	for {

		command, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error in getting command from reader")
			return
		}
		encryptedBytes, err := EncryptMessage(tunnel, command)

		if err != nil {
			fmt.Printf("Failed to get encrypted bytes")

		} else {
			fmt.Printf("Encrypted message %v\n", encryptedBytes)
			_, err := (*conn).Write(encryptedBytes)
			if err != nil {
				printErr(err)
				return
			}
		}
	}
}

func ReadStream(conn *net.Conn) {
	buffer := make([]byte, 1024)
	for {
		n, err := (*conn).Read(buffer)
		if err != nil {
			fmt.Printf("Error in reading from error %v\n", err)
			return
		} else {
			fmt.Printf("Received message %v from %s with %d bytes\n", buffer, (*conn).RemoteAddr(), n)
		}
	}
}

func setupEncryptedTunnel(conn *net.Conn) (*EncryptedTunnel, error) {
	tunnel := NewEncryptedTunnel()

	primeNumber, err := readPrimeNumber(conn)
	if err != nil {
		printErr(err)
		return tunnel, err
	}

	fmt.Printf("This is prime number %v\n", primeNumber.Bytes())

	generator, err := readGenerator(conn)
	if err != nil {
		printErr(err)
		return tunnel, err
	}

	fmt.Printf("This is generator %v\n", generator.Bytes())

	clientKey, err := readPublicKey(conn)

	if err != nil {
		printErr(err)
		return tunnel, err
	}

	fmt.Printf("This is client key %v\n", clientKey.Bytes())

	serverSecret, err := generateServerSecret(primeNumber)
	if err != nil {
		printErr(err)
		return tunnel, err
	}

	fmt.Printf("This is server secret %v\n", serverSecret.Bytes())

	sendServerPublicKey(primeNumber, generator, serverSecret, conn)

	sessionKey := generateSessionKey(clientKey, serverSecret, primeNumber)

	fmt.Printf("This is session key %v\n", sessionKey.Bytes())
	tunnel.Conn = conn
	tunnel.Key = sessionKey

	// hash the key to 32 bytes for AES 256
	tunnel.KeyBytes = sha256.Sum256(sessionKey.Bytes())

	return tunnel, err

}
