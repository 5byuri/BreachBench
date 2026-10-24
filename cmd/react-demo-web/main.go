// react-demo-web exposes only the explicit Node training lab through host loopback.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const relayJS = `const net=require("node:net");const s=net.connect({host:"127.0.0.1",port:Number(process.argv[1])});const timer=setTimeout(()=>s.destroy(),60000);process.stdin.pipe(s);s.pipe(process.stdout);s.on("error",()=>{process.exitCode=1});s.on("close",()=>{clearTimeout(timer);process.stdin.destroy();process.stdout.end()});process.stdin.on("error",()=>s.destroy());process.stdout.on("error",()=>s.destroy());`

type config struct {
	container           string
	port, containerPort int
}

func parseConfig(args []string) (config, error) {
	var c config
	f := flag.NewFlagSet("react-demo-web", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&c.container, "container", "", "Existing Node demo container")
	f.IntVar(&c.port, "port", 3000, "Host loopback port")
	f.IntVar(&c.containerPort, "container-port", 3000, "Container loopback port")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return c, flag.ErrHelp
		}
		return c, errors.New("invalid forwarder arguments")
	}
	if f.NArg() != 0 || len(c.container) == 0 || len(c.container) > 128 || c.port < 1 || c.port > 65535 || c.containerPort < 1 || c.containerPort > 65535 {
		return c, errors.New("a bounded Docker container name and valid ports are required")
	}
	for i, r := range c.container {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || (i > 0 && (r == '_' || r == '.' || r == '-'))) {
			return c, errors.New("invalid Docker container name")
		}
	}
	return c, nil
}

func loopbackAddress(c config) string { return "127.0.0.1:" + strconv.Itoa(c.port) }

type commandFactory func(context.Context, string, ...string) *exec.Cmd

func relay(ctx context.Context, connection net.Conn, c config, command commandFactory) error {
	cmd := command(ctx, "docker", "exec", "-i", c.container, "node", "-e", relayJS, strconv.Itoa(c.containerPort))
	cmd.Stdout, cmd.Stderr = connection, io.Discard
	cmd.WaitDelay = 250 * time.Millisecond
	input, err := cmd.StdinPipe()
	if err != nil {
		return errors.New("cannot open demo relay input")
	}
	defer input.Close()
	stop := context.AfterFunc(ctx, func() { connection.Close(); input.Close() })
	defer stop()
	if err := cmd.Start(); err != nil {
		return errors.New("cannot start demo relay")
	}
	copied := make(chan struct{})
	go func() {
		_, _ = io.Copy(input, connection)
		_ = input.Close()
		close(copied)
	}()
	err = cmd.Wait()
	// Closing both endpoints releases the input copier even if the browser stays open.
	connection.Close()
	input.Close()
	<-copied
	return err
}

type relayFunc func(context.Context, net.Conn, config) error

func serve(ctx context.Context, listener net.Listener, c config, forward relayFunc, wait func(context.Context, string)) error {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer func() { cancel(); listener.Close(); workers.Wait(); stop() }()
	workers.Add(1)
	go func() { defer workers.Done(); wait(ctx, c.container); cancel() }()
	capacity := make(chan struct{}, 16)
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("localhost listener failed")
		}
		select {
		case capacity <- struct{}{}:
		default:
			connection.Close()
			continue
		}
		workers.Add(1)
		go func(connection net.Conn) {
			defer workers.Done()
			defer func() { <-capacity }()
			defer connection.Close()
			child, done := context.WithTimeout(ctx, time.Minute)
			defer done()
			_ = connection.SetDeadline(time.Now().Add(time.Minute))
			_ = forward(child, connection, c)
		}(connection)
	}
}

func run(ctx context.Context, c config, out io.Writer) error {
	listener, err := net.Listen("tcp4", loopbackAddress(c))
	if err != nil {
		return errors.New("cannot bind the host loopback port")
	}
	fmt.Fprintf(out, "http://%s -> %s (PID %d)\n", loopbackAddress(c), c.container, os.Getpid())
	return serve(ctx, listener, c, func(ctx context.Context, connection net.Conn, c config) error {
		return relay(ctx, connection, c, exec.CommandContext)
	}, func(ctx context.Context, container string) {
		cmd := exec.CommandContext(ctx, "docker", "wait", container)
		cmd.WaitDelay = 250 * time.Millisecond
		_ = cmd.Run()
	})
}

func main() {
	c, err := parseConfig(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		fmt.Println("Usage: react-demo-web --container NAME [--port 3000] [--container-port 3000]; localhost-only Node lab relay")
		return
	}
	if err == nil {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		err = run(ctx, c, os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
