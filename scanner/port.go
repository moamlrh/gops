package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

type PortScanner struct {
	ip      string
	workers int
}

func NewPortScanner(ip string, workers int) *PortScanner {
	return &PortScanner{
		ip:      ip,
		workers: workers,
	}
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
