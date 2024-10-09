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
	timeout time.Duration
}

func NewPortScanner(ip string, workers int, timeout time.Duration) *PortScanner {
	return &PortScanner{
		ip:      ip,
		workers: workers,
		timeout: timeout,
	}
}

func (ps *PortScanner) Run(ctx context.Context, startPort, endPort int, rateLimiter *rate.Limiter) {
	portsChan := make(chan int, ps.workers)

	var wg sync.WaitGroup
	var scannedPorts int32 = 0
	lastReportedMilestone := int32(0)
	mileStones := []int32{1000, 10000, 20000, 30000, 40000, 50000, 60000}

	wg.Add(1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				wg.Done()
				return
			default:
				time.Sleep(1 * time.Second)
				scanned := atomic.LoadInt32(&scannedPorts)
				for _, milestone := range mileStones {
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
		}
	}()

	for i := 0; i < ps.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsChan {
				if err := rateLimiter.Wait(ctx); err != nil {
					return
				}

				select {
				case <-ctx.Done():
					return
				default:
					if ps.ScanPort(ctx, ps.ip, port) {
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

func (ps *PortScanner) ScanPort(ctx context.Context, ip string, port int) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, ps.timeout)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}
