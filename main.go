package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/moamlrh/gops/scanner"
	"golang.org/x/time/rate"
)

func main() {
	now := time.Now()
	ip := flag.String("ip", "142.250.187.110", "IP address to scan")
	workers := flag.Int("workers", 250, "Number of concurrent workers")
	startPort := flag.Int("start", 1, "Start port")
	endPort := flag.Int("end", 40000, "End port")
	timeout := flag.Duration("timeout", 500*time.Millisecond, "Timeout for each port scan")
	rateLimit := flag.Float64("rate", 1000, "Maximum scan rate (ports per second)")
	flag.Parse()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		<-signalChan
		log.Println("Shutting down...")
		os.Exit(0)
	}()

	defer func() {
		log.Printf("Execution time: %v", time.Since(now))
	}()

	ps := scanner.NewPortScanner(*ip, *workers)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rateLimiter := rate.NewLimiter(rate.Limit(*rateLimit), 1)

	log.Printf("Scanning ports %d to %d on %s...\n", *startPort, *endPort, *ip)
	ps.Start(ctx, *startPort, *endPort, *timeout, rateLimiter)
	log.Printf("Scanning completed")
}
