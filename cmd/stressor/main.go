// Command stressor is an S1AP load generator that simulates multiple UEs
// attaching to the MME via a single virtual eNB SCTP connection.
//
// Usage:
//
//	stressor -mme 10.200.200.1:36412 -ues 100 -rate 5 -k <hex-key> -opc <hex-opc>
//
// Security: the stressor advertises EIA0/EEA0 only, so the MME selects null
// integrity + null ciphering. This avoids computing NAS MACs while still
// exercising the full S1AP + NAS + S6a + DB path.
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Config holds all stressor runtime parameters.
type Config struct {
	MMEAddr     string
	MCC         string
	MNC         string
	TAC         uint16
	ENBID       uint32
	ENBIP       []byte // 4-byte IPv4 reported as eNB S1-U GTP-U address in ICS Response
	IMSIBase    string
	K           []byte // 16-byte auth key (default for all UEs)
	OPC         []byte // 16-byte OPc (default for all UEs)
	Credentials map[string][2][]byte // IMSI → [K, OPC] (per-UE override)
	NumUEs      int
	Rate        float64 // UEs per second
}

// Stats tracks stressor progress with atomic counters.
type Stats struct {
	Started   atomic.Int64
	Completed atomic.Int64
	Failed    atomic.Int64
}

func main() {
	mmeAddr   := flag.String("mme",          "127.0.0.1:36412",      "MME S1AP address (host:port)")
	numUEs    := flag.Int("ues",             10,                      "total number of UEs to attach")
	rate      := flag.Float64("rate",        1.0,                     "UE attach rate (per second)")
	mcc       := flag.String("mcc",          "204",                   "MCC (3 digits)")
	mnc       := flag.String("mnc",          "95",                    "MNC (2 or 3 digits)")
	tac       := flag.Uint("tac",            1,                       "TAC (tracking area code)")
	enbID     := flag.Uint("enb-id",         0x0001,                  "eNB ID (macro 20-bit)")
	enbS1UIP  := flag.String("enb-s1u-ip",   "127.0.0.1",            "eNB S1-U GTP-U IPv4 address reported in ICS Response")
	imsiBase  := flag.String("imsi-base",    "204950000000001",       "IMSI of the first UE")
	kHex      := flag.String("k",            "465B5CE8B199B49FAA5F0A2EE238A6BC", "K (hex, 32 chars) — default for all UEs")
	opcHex    := flag.String("opc",          "E8ED289DEBA952E4283B54E88E6183CA", "OPC (hex, 32 chars) — default for all UEs")
	credsFile := flag.String("credentials",  "",                      "CSV file with per-UE credentials: imsi,k,opc")
	flag.Parse()

	k, err := hex.DecodeString(*kHex)
	if err != nil || len(k) != 16 {
		fmt.Fprintf(os.Stderr, "error: K must be 32 hex chars: %v\n", err)
		os.Exit(1)
	}
	opc, err := hex.DecodeString(*opcHex)
	if err != nil || len(opc) != 16 {
		fmt.Fprintf(os.Stderr, "error: OPC must be 32 hex chars: %v\n", err)
		os.Exit(1)
	}

	creds, err := loadCredentials(*credsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading credentials: %v\n", err)
		os.Exit(1)
	}

	enbIP := net.ParseIP(*enbS1UIP).To4()
	if enbIP == nil {
		fmt.Fprintf(os.Stderr, "error: -enb-s1u-ip %q is not a valid IPv4 address\n", *enbS1UIP)
		os.Exit(1)
	}

	cfg := &Config{
		MMEAddr:     *mmeAddr,
		MCC:         *mcc,
		MNC:         *mnc,
		TAC:         uint16(*tac),
		ENBID:       uint32(*enbID),
		ENBIP:       enbIP,
		IMSIBase:    *imsiBase,
		K:           k,
		OPC:         opc,
		Credentials: creds,
		NumUEs:      *numUEs,
		Rate:        *rate,
	}

	fmt.Printf("Connecting to MME %s ...\n", cfg.MMEAddr)
	enb, err := NewENB(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ENB connect failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("S1 Setup complete. Running %d UEs at %.1f/s  (IMSI base %s)\n",
		cfg.NumUEs, cfg.Rate, cfg.IMSIBase)

	stats := &Stats{}

	doneCh := make(chan struct{})
	go printStats(stats, doneCh)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	interval := time.Duration(float64(time.Second) / cfg.Rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	spawned := 0
loop:
	for spawned < cfg.NumUEs {
		select {
		case <-ticker.C:
			i := spawned
			go func() {
				stats.Started.Add(1)
				ue := NewUE(cfg, enb, i)
				if err := ue.Attach(); err != nil {
					stats.Failed.Add(1)
				} else {
					stats.Completed.Add(1)
				}
			}()
			spawned++
		case <-sigCh:
			break loop
		}
	}

	// Wait for remaining UEs or second signal
	if spawned == cfg.NumUEs {
		// Poll until all done or signal
		for {
			done := stats.Completed.Load() + stats.Failed.Load()
			if done >= int64(cfg.NumUEs) {
				break
			}
			select {
			case <-sigCh:
				goto exit
			case <-time.After(100 * time.Millisecond):
			}
		}
	}

exit:
	close(doneCh)
	time.Sleep(50 * time.Millisecond) // let stats goroutine flush
	fmt.Printf("\nDone: started=%d  completed=%d  failed=%d\n",
		stats.Started.Load(), stats.Completed.Load(), stats.Failed.Load())
}

// loadCredentials parses an optional CSV file (imsi,k,opc per line, header optional).
// Returns nil map (not an error) when path is empty.
func loadCredentials(path string) (map[string][2][]byte, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	creds := make(map[string][2][]byte)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "imsi") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 3 {
			return nil, fmt.Errorf("bad line %q: expected imsi,k,opc", line)
		}
		imsi := strings.TrimSpace(parts[0])
		k, err := hex.DecodeString(strings.TrimSpace(parts[1]))
		if err != nil || len(k) != 16 {
			return nil, fmt.Errorf("imsi %s: bad K %q", imsi, parts[1])
		}
		opc, err := hex.DecodeString(strings.TrimSpace(parts[2]))
		if err != nil || len(opc) != 16 {
			return nil, fmt.Errorf("imsi %s: bad OPC %q", imsi, parts[2])
		}
		creds[imsi] = [2][]byte{k, opc}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return creds, nil
}

func printStats(s *Stats, done <-chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var prev int64
	for {
		select {
		case <-done:
			return
		case now := <-t.C:
			comp := s.Completed.Load()
			tps := comp - prev
			prev = comp
			fmt.Printf("[%s] started=%-5d  completed=%-5d  failed=%-5d  rate=%d/s\n",
				now.Format("15:04:05"),
				s.Started.Load(), comp, s.Failed.Load(), tps)
		}
	}
}
