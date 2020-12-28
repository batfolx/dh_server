package main

import (
	"bufio"
	"fmt"
	"github.com/gliderlabs/ssh"
	"io"
	"log"
	"os"
	"../tcp_server"
)



func main() {
	tcp_server.SetupListener()
}

func ReadCommand(s *ssh.Session) {

	buffer := make([]byte, 1024)
	for {

		n, err := (*s).Read(buffer)
		if err != nil {
			fmt.Printf("Error in reading from %s, %v\n", (*s).RemoteAddr(), err)
			return
		}

		fmt.Printf("Buffer %d bytes received with data %s\n", n, string(buffer))



	}
}

func StartSSHServer() {
	ssh.Handle(func(s ssh.Session) {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("Got a connection from  %s\n", s.RemoteAddr())
		go ReadCommand(&s)
		for {

			command, err := reader.ReadString('\n')
			if err != nil {
				fmt.Printf("Error in reading string %v\n", err)
				return
			}
			io.WriteString(s, command)

		}



	})


	log.Fatal(ssh.ListenAndServe(":9000", nil))
}