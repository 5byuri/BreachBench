package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConfigCannotExposeNonLoopbackOrInjectDockerArguments(t *testing.T) {
	for _, args := range [][]string{
		nil, {"--container", "-other"}, {"--container", "bad/name"}, {"--container", "bad name"},
		{"--container", strings.Repeat("a", 129)}, {"--container", "demo", "--port", "0"},
		{"--container", "demo", "--container-port", "65536"}, {"--container", "demo", "extra"},
		{"--container", "demo", "--host", "0.0.0.0"}, {"--container", "demo", "--bind", "::"},
	} {
		if _, err := parseConfig(args); err == nil {
			t.Fatalf("accepted unsafe configuration: %v", args)
		}
	}
	c, err := parseConfig([]string{"--container", "demo_1-node.lab", "--port", "3001"})
	if err != nil || c.containerPort != 3000 || loopbackAddress(c) != "127.0.0.1:3001" {
		t.Fatalf("invalid loopback configuration: %+v %v", c, err)
	}
}

func relayChild(ctx context.Context, mode string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRelayChildProcess$")
	cmd.Env = append(os.Environ(), "BREACHBENCH_RELAY_TEST="+mode)
	return cmd
}

func TestRelayChildProcess(t *testing.T) {
	switch os.Getenv("BREACHBENCH_RELAY_TEST") {
	case "echo":
		_, _ = io.Copy(os.Stdout, os.Stdin)
	case "exit":
		_, _ = os.Stdout.Write([]byte("done"))
	case "block":
		time.Sleep(time.Hour)
	default:
		return
	}
	os.Exit(0)
}

func TestRelayPreservesBytesAndUsesOnlyFixedDockerArgv(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := config{container: "owned-demo", containerPort: 3000}
	done := make(chan error, 1)
	go func() {
		done <- relay(ctx, server, c, func(ctx context.Context, name string, args ...string) *exec.Cmd {
			want := []string{"exec", "-i", "owned-demo", "node", "-e", relayJS, "3000"}
			if name != "docker" || !reflect.DeepEqual(args, want) {
				t.Errorf("unexpected child command: %s %v", name, args)
			}
			return relayChild(ctx, "echo")
		})
	}()
	payload := []byte("POST /action HTTP/1.1\r\nHost: localhost:3000\r\n\r\n\x00binary\xffbody")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(payload, got) {
		t.Fatalf("relay changed HTTP/body bytes: %q %v", got, err)
	}
	client.Close()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("relay leaked after client closed")
	}
}

func TestRelayReleasesInputCopierOnUpstreamExitOrCancellation(t *testing.T) {
	for _, mode := range []string{"exit", "block"} {
		t.Run(mode, func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- relay(ctx, server, config{container: "demo", containerPort: 3000}, func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
					return relayChild(ctx, mode)
				})
			}()
			if mode == "exit" {
				got := make([]byte, 4)
				client.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.ReadFull(client, got); err != nil || string(got) != "done" {
					t.Fatalf("upstream output lost: %q %v", got, err)
				}
			} else {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("relay input copier or child did not stop")
			}
		})
	}
}

type pipeListener struct {
	closed   chan struct{}
	incoming chan net.Conn
	once     sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case connection := <-l.incoming:
		return connection, nil
	}
}
func (l *pipeListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func TestContainerStopClosesListenerWithoutDocker(t *testing.T) {
	l := &pipeListener{closed: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- serve(context.Background(), l, config{}, func(context.Context, net.Conn, config) error {
			t.Error("unexpected connection")
			return nil
		}, func(context.Context, string) {})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("container stop left listener running")
	}
}

func TestConnectionLimitRejectsSeventeenthAndCancellationStopsAll(t *testing.T) {
	l := &pipeListener{closed: make(chan struct{}), incoming: make(chan net.Conn)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 16)
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, l, config{}, func(ctx context.Context, _ net.Conn, _ config) error {
			started <- struct{}{}
			<-ctx.Done()
			return nil
		}, func(ctx context.Context, _ string) { <-ctx.Done() })
	}()
	for i := 0; i < 16; i++ {
		server, client := net.Pipe()
		defer client.Close()
		l.incoming <- server
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("allowed connection did not start")
		}
	}
	server, client := net.Pipe()
	defer client.Close()
	l.incoming <- server
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("excess connection was not immediately closed: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation left listener or relay workers running")
	}
}
