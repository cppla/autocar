// Command stealth-campaign-toy is a local-only UDP echo fixture for exercising
// the capture driver. Its traffic is not AutoCAR, Hysteria, or cover evidence.
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: stealth-campaign-toy server|client [flags]")
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = server(os.Args[2:])
	case "client":
		err = client(os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fatalf("%v", err)
	}
}

func server(args []string) error {
	flags := flag.NewFlagSet("server", flag.ContinueOnError)
	listen := flags.String("listen", ":8443", "UDP listen address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	conn, err := net.ListenPacket("udp4", *listen)
	if err != nil {
		return err
	}
	defer conn.Close()
	buffer := make([]byte, 2048)
	for {
		n, peer, readErr := conn.ReadFrom(buffer)
		if readErr != nil {
			return readErr
		}
		if _, writeErr := conn.WriteTo(buffer[:n], peer); writeErr != nil {
			return writeErr
		}
	}
}

func client(args []string) error {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	serverAddress := flags.String("server", "", "numeric server host:port")
	workload := flags.String("workload", "", "fixture workload label")
	seed := flags.Int64("seed", 0, "fixture seed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *serverAddress == "" || *workload == "" {
		return fmt.Errorf("--server and --workload are required")
	}
	conn, err := net.DialTimeout("udp4", *serverAddress, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return err
	}
	for index := 0; index < 4; index++ {
		payload := []byte("toy-only|" + *workload + "|" + strconv.FormatInt(*seed, 10) + "|" + strconv.Itoa(index))
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, reply); err != nil {
			return err
		}
		if string(reply) != string(payload) {
			return fmt.Errorf("echo mismatch")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

func fatalf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, "stealth-campaign-toy: "+format+"\n", values...)
	os.Exit(1)
}
