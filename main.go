package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/moamlrh/gops/scanner"
	"golang.org/x/time/rate"
)

func main() {
	now := time.Now()
	ip := flag.String("ip", "", "IP address to scan")
	workers := flag.Int("workers", 250, "Number of concurrent workers")
	startPort := flag.Int("start", 1, "Start port")
	endPort := flag.Int("end", 10000, "End port")
	timeout := flag.Duration("timeout", 500*time.Millisecond, "Timeout for each port scan")
	rateLimit := flag.Float64("rate", 1000, "Maximum scan rate (ports per second)")
	flag.Parse()

	if *ip == "" {
		log.Fatal("Please provide an IP address to scan")
	}
	if *startPort < 1 || *startPort > 65535 {
		log.Fatal("Invalid start port")
	}
	if *endPort < 1 || *endPort > 65535 {
		log.Fatal("Invalid end port")
	}
	if *startPort > *endPort {
		log.Fatal("Start port cannot be greater than end port")
	}
	if *workers < 1 {
		log.Fatal("Number of workers should be greater than 0")
	}
	if *rateLimit < 1 {
		log.Fatal("Rate limit should be greater than 0")
	}

	ps := scanner.NewPortScanner(*ip, *workers, *timeout)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		log.Println("Shutting down...")
		log.Printf("Execution time: %v\n", time.Since(now))
		cancel()
	}()

	rateLimiter := rate.NewLimiter(rate.Limit(*rateLimit), 1)
	log.Printf("Scanning ports %d to %d on %s...\n", *startPort, *endPort, *ip)
	ps.Run(ctx, *startPort, *endPort, rateLimiter)
}
