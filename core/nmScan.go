package core

import (
	"context"
	"github.com/Ullaakut/nmap/v2"
	"github.com/rambleZzz/nmScan_go/common"
	"log"
	"sync"
	"time"
)

func NmScan(ip string, ports string, ch_result chan *nmap.Run, wg *sync.WaitGroup) {
	var scanner *nmap.Scanner
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	//nmap扫描配置项
	if common.NMAPsV == true {
		scanner, err = nmap.NewScanner(
			nmap.WithTargets(ip),
			nmap.WithPorts(ports),
			nmap.WithContext(ctx),
			nmap.WithServiceInfo(),
			nmap.WithSkipHostDiscovery(),
		)
	} else {
		scanner, err = nmap.NewScanner(
			nmap.WithTargets(ip),
			nmap.WithPorts(ports),
			nmap.WithContext(ctx),
			//nmap.WithServiceInfo(),
			nmap.WithSkipHostDiscovery(),
		)
	}
	if err != nil {
		log.Fatalf("无法创建nmap scanner: %v", err)
	}
	result, warnings, err := scanner.Run()
	if err != nil {
		log.Fatalf("无法运行nmap scan: %v", err)
	}
	if warnings != nil {
		log.Printf("警告: %v", warnings)
	}
	ch_result <- result
	wg.Add(1)
}
