package tcp_server

import (
	"crypto/sha256"
	"fmt"
	"net"
	"time"
)

func SetupListener() {
	// sets up the TCP listener
	addr := "127.0.0.1:9000"

	var listener net.Listener = nil

	// keep trying until we can get a listner
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

	fmt.Printf("Server listening on %s\n", addr)
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
	// handles connection between a connection and a client
	tunnel, err := setupEncryptedTunnel(conn)
	if err != nil {
		printErr(err)
		return
	}

	ReadStream(tunnel)

}

func ReadStream(tunnel *EncryptedTunnel) {

	buffer := make([]byte, BUFFER_SIZE)
	conn := tunnel.Conn
	for {

		// read encrypted data
		n, err := (*conn).Read(buffer)
		if err != nil {
			printErr(err)
			return
		}
		plaintext, err := DecryptData(buffer[0:n], tunnel)
		if err != nil {
			printErr(err)
			return
		}
		fmt.Printf("Decrypted plaintext to %s\n", plaintext)

	}

}

func setupEncryptedTunnel(conn *net.Conn) (*EncryptedTunnel, error) {
	tunnel := NewEncryptedTunnel()

	// get prime number from client
	primeNumber, err := readPrimeNumber(conn)
	if err != nil {
		printErr(err)
		return tunnel, err
	}

	fmt.Printf("This is prime number %v\n", primeNumber.Bytes())

	// get generator from client
	generator, err := readGenerator(conn)
	if err != nil {
		printErr(err)
		return tunnel, err
	}

	fmt.Printf("This is generator %v\n", generator.Bytes())

	// get key from client
	clientKey, err := readPublicKey(conn)

	if err != nil {
		printErr(err)
		return tunnel, err
	}

	fmt.Printf("This is client key %v\n", clientKey.Bytes())

	// generate server secret
	serverSecret, err := generateServerSecret(primeNumber)
	if err != nil {
		printErr(err)
		return tunnel, err
	}

	fmt.Printf("This is server secret %v\n", serverSecret.Bytes())

	// send the server key to the client
	sendServerPublicKey(primeNumber, generator, serverSecret, conn)

	// generate session key
	sessionKey := generateSessionKey(clientKey, serverSecret, primeNumber)

	fmt.Printf("This is session key %v\n", sessionKey.Bytes())
	tunnel.Conn = conn
	tunnel.Key = sessionKey

	// hash the key to 32 bytes for AES 256
	tunnel.KeyBytes = sha256.Sum256(sessionKey.Bytes())

	// return the tunnel and error
	return tunnel, nil

}
