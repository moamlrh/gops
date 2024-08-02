package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

type PortScanner struct {
	ip      string
	workers int
}

func ScanPort(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}

func (ps *PortScanner) Start(ctx context.Context, startPort, endPort int, timeout time.Duration, rateLimiter *rate.Limiter) {
	portsChan := make(chan int, ps.workers)

	var wg sync.WaitGroup
	var scannedPorts int32 = 0
	lastReportedMilestone := int32(0)
	minleStones := []int32{1000, 10000, 20000, 30000, 40000, 50000, 60000}

	go func() {
		for {
			time.Sleep(1 * time.Second)
			scanned := atomic.LoadInt32(&scannedPorts)
			for _, milestone := range minleStones {
				if scanned >= milestone && lastReportedMilestone < milestone {
					log.Printf("Scanned %d ports", milestone)
					atomic.StoreInt32(&lastReportedMilestone, milestone)
					break
				}
			}
			if scanned >= int32(endPort-startPort+1) {
				return
			}
		}
	}()

	for i := 0; i < ps.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsChan {
				if err := rateLimiter.Wait(ctx); err != nil {
					log.Printf("Rate limiter error: %v", err)
					return
				}

				select {
				case <-ctx.Done():
					return
				default:
					if ScanPort(ctx, ps.ip, port, timeout) {
						log.Printf("\033[32mPort %d is open\033[0m", port)
					}
					atomic.AddInt32(&scannedPorts, 1)
				}
			}
		}()
	}

	go func() {
		defer close(portsChan)
		for port := startPort; port <= endPort; port++ {
			select {
			case <-ctx.Done():
				return
			case portsChan <- port:
			}
		}
	}()

	wg.Wait()
}

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

	ps := &PortScanner{
		ip:      *ip,
		workers: *workers,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rateLimiter := rate.NewLimiter(rate.Limit(*rateLimit), 1)

	log.Printf("Scanning ports %d to %d on %s...\n", *startPort, *endPort, *ip)
	ps.Start(ctx, *startPort, *endPort, *timeout, rateLimiter)
	log.Printf("Scanning completed")
}
