// Test Go DERP client connectivity to Erlang DERP server
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/types/key"
)

var (
	serverAddr = flag.String("server", "localhost:8080", "DERP server address (host:port)")
	useTLS     = flag.Bool("tls", false, "Use TLS connection")
	verbose    = flag.Bool("v", false, "Verbose output")
)

func main() {
	flag.Parse()

	if err := runTests(); err != nil {
		log.Fatalf("FAIL: %v", err)
	}
	fmt.Println("PASS: All interop tests passed")
}

func runTests() error {
	// Test 1: HTTP upgrade connection and handshake
	if err := testHTTPUpgrade(); err != nil {
		return fmt.Errorf("HTTP upgrade test: %w", err)
	}

	// Test 2: Two clients communicate
	if err := testTwoClients(); err != nil {
		return fmt.Errorf("two clients test: %w", err)
	}

	return nil
}

func testHTTPUpgrade() error {
	log.Println("Test: HTTP upgrade connection...")

	priv := key.NewNode()

	client, err := connectClient(priv)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	// Connection successful - handshake completed
	log.Println("  - Connection and handshake successful")
	log.Println("  PASS")
	return nil
}

func testTwoClients() error {
	log.Println("Test: Two clients communication...")

	// Create two clients with different keys
	priv1 := key.NewNode()
	priv2 := key.NewNode()

	client1, err := connectClient(priv1)
	if err != nil {
		return fmt.Errorf("connect client1: %w", err)
	}
	defer client1.Close()

	client2, err := connectClient(priv2)
	if err != nil {
		return fmt.Errorf("connect client2: %w", err)
	}
	defer client2.Close()

	// Start receiving on client2
	recvCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		for {
			msg, err := client2.Recv()
			if err != nil {
				errCh <- err
				return
			}
			switch m := msg.(type) {
			case derp.ReceivedPacket:
				recvCh <- m.Data
				return
			}
		}
	}()

	// Send from client1 to client2
	testData := []byte("Hello from Go client!")
	pub2 := priv2.Public()
	if err := client1.Send(pub2, testData); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	log.Println("  - Sent packet from client1 to client2")

	// Wait for receipt
	select {
	case data := <-recvCh:
		if string(data) != string(testData) {
			return fmt.Errorf("received data mismatch: got %q, want %q", data, testData)
		}
		log.Println("  - Client2 received packet correctly")
	case err := <-errCh:
		return fmt.Errorf("recv error: %w", err)
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for packet")
	}

	log.Println("  PASS")
	return nil
}

func connectClient(priv key.NodePrivate) (*derphttp.Client, error) {
	scheme := "http"
	if *useTLS {
		scheme = "https"
	}

	serverURL := &url.URL{
		Scheme: scheme,
		Host:   *serverAddr,
		Path:   "/derp",
	}

	client, err := derphttp.NewClient(priv, serverURL.String(), log.Printf)
	if err != nil {
		return nil, err
	}

	// Set custom dialer for plain HTTP
	if !*useTLS {
		client.SetURLDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	if *verbose {
		log.Printf("Connected to %s, server key: %s", *serverAddr, client.ServerPublicKey())
	}

	return client, nil
}
