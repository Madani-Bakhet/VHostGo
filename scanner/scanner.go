package scanner

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Result holds the data from a successful scan
type Result struct {
	Subdomain     string `json:"subdomain"`
	IP            string `json:"ip"`
	Protocol      string `json:"protocol"`
	Port          string `json:"port"`
	Status        int    `json:"status"`
	ContentLength int64  `json:"content_length"`
}

// Config holds the configuration for the scanner
type Config struct {
	Domain       string
	WordlistPath string
	IPs          string // Added
	SaveIPsFile  string // Added
	OutputFormat string
	OutputFile   string
	NumIPs       int
	Protocols    []string
	Ports        []string
	Timeout      time.Duration
	Concurrency  int
	ResolveNew   bool
}

// job represents a single scan task
type job struct {
	subdomain string
	ip        string
	protocol  string
	port      string
}

// Baseline holds the characteristics of a non-existent vhost response
type Baseline struct {
	Status        int
	ContentLength int64
	BodyHash      string
}

// Run starts the vhost scanning process
func Run(config Config) {
	// --- Phase 1: IP Discovery ---
	fmt.Println("[*] Phase 1: Discovering IP addresses...")

	targetIPs := &sync.Map{}
	var wgResolvers sync.WaitGroup

	// If IPs are specified directly, use them. Otherwise, resolve the domain.
	if config.IPs != "" {
		fmt.Printf("[+] Using specified IP addresses: %s\n", config.IPs)
		providedIPs := strings.Split(config.IPs, ",")
		for _, ipStr := range providedIPs {
			ipStr = strings.TrimSpace(ipStr)
			if net.ParseIP(ipStr) == nil {
				fmt.Printf("[-] Warning: '%s' is not a valid IP address. Skipping.\n", ipStr)
				continue
			}
			targetIPs.Store(ipStr, struct{}{})
		}
	} else {
		// Resolve base domain if no specific IPs are provided
		initialIPs, err := net.LookupHost(config.Domain)
		if err != nil {
			fmt.Printf("[-] Error resolving base domain %s: %v\n", config.Domain, err)
			return
		}
		fmt.Printf("[+] Found %d IP(s) for base domain %s: %v\n", len(initialIPs), config.Domain, initialIPs)
		for i, ip := range initialIPs {
			if config.NumIPs > 0 && i >= config.NumIPs {
				break
			}
			targetIPs.Store(ip, struct{}{})
		}
	}

	// Read wordlist
	subdomains, err := readLines(config.WordlistPath)
	if err != nil {
		fmt.Printf("[-] Error reading wordlist file: %v\n", err)
		return
	}
	fmt.Printf("[+] Loaded %d subdomains from %s\n", len(subdomains), config.WordlistPath)

	// Resolve new subdomains if requested
	if config.ResolveNew {
		fmt.Println("[*] Resolving new subdomains...")
		resolverJobs := make(chan string, len(subdomains))
		for i := 0; i < config.Concurrency; i++ {
			wgResolvers.Add(1)
			go func() {
				defer wgResolvers.Done()
				for sub := range resolverJobs {
					fqdn := sub + "." + config.Domain
					ips, err := net.LookupHost(fqdn)
					if err == nil {
						for _, ip := range ips {
							targetIPs.Store(ip, struct{}{})
						}
					}
				}
			}()
		}
		for _, sub := range subdomains {
			resolverJobs <- sub
		}
		close(resolverJobs)
		wgResolvers.Wait()
	}

	var finalIPs []string
	targetIPs.Range(func(key, value interface{}) bool {
		finalIPs = append(finalIPs, key.(string))
		return true
	})

	// Save discovered IPs to a file if requested
	if config.SaveIPsFile != "" {
		err := saveIPsToFile(config.SaveIPsFile, finalIPs)
		if err != nil {
			fmt.Printf("[-] Error saving IP addresses to %s: %v\n", config.SaveIPsFile, err)
		} else {
			fmt.Printf("[+] Saved %d unique IP addresses to %s\n", len(finalIPs), config.SaveIPsFile)
		}
	}

	if len(finalIPs) == 0 {
		fmt.Println("[-] No target IP addresses found. Exiting.")
		return
	}
	fmt.Printf("[*] Total unique IPs to scan: %d %v\n", len(finalIPs), finalIPs)

	// --- Phase 1.5: Establish Baseline ---
	fmt.Println("\n[*] Phase 1.5: Establishing baseline to filter junk results...")
	baseline := establishBaseline(config, finalIPs[0])
	if baseline.BodyHash == "" {
		fmt.Println("[-] Warning: Could not establish a reliable baseline. Results may include false positives.")
	} else {
		fmt.Printf("[+] Baseline established. Filtering responses with Status=%d, Length=%d, Hash=%s...\n", baseline.Status, baseline.ContentLength, baseline.BodyHash[:10])
	}

	// --- Phase 2: VHost Scanning ---
	fmt.Println("\n[*] Phase 2: Scanning for virtual hosts...")
	jobs := make(chan job)
	results := make(chan Result)
	var wgScanners sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wgScanners.Add(1)
		go worker(config, baseline, jobs, results, &wgScanners)
	}
	go func() {
		for _, sub := range subdomains {
			for _, ip := range finalIPs {
				for _, proto := range config.Protocols {
					for _, port := range config.Ports {
						jobs <- job{subdomain: sub, ip: ip, protocol: proto, port: port}
					}
				}
			}
		}
		close(jobs)
	}()
	var collectedResults []Result
	var collectWG sync.WaitGroup
	collectWG.Add(1)
	go func() {
		defer collectWG.Done()
		for res := range results {
			collectedResults = append(collectedResults, res)
			if config.OutputFormat == "simple" {
				fmt.Printf("Found: %s://%s.%s:%s on IP %s (Status: %d)\n", res.Protocol, res.Subdomain, config.Domain, res.Port, res.IP, res.Status)
			}
		}
	}()
	wgScanners.Wait()
	close(results)
	collectWG.Wait()

	// --- Phase 3: Output ---
	fmt.Println("\n[*] Phase 3: Scan complete. Generating output...")
	writeOutput(config, collectedResults)
	fmt.Println("[+] Done.")
}

// ... (establishBaseline and worker functions remain unchanged) ...
func establishBaseline(config Config, ip string) Baseline {
	rand.Seed(time.Now().UnixNano())
	randomSubdomain := fmt.Sprintf("baseline-check-%d", rand.Intn(100000))
	fqdn := randomSubdomain + "." + config.Domain
	proto := config.Protocols[0]
	port := config.Ports[0]
	url := fmt.Sprintf("%s://%s:%s", proto, ip, port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return Baseline{}
	}
	req.Host = fqdn
	req.Header.Set("User-Agent", "VHostGo/1.0 (Baseline Check)")
	client := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return Baseline{}
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Baseline{}
	}
	hash := sha256.Sum256(bodyBytes)
	return Baseline{
		Status:        resp.StatusCode,
		ContentLength: resp.ContentLength,
		BodyHash:      hex.EncodeToString(hash[:]),
	}
}
func worker(config Config, baseline Baseline, jobs <-chan job, results chan<- Result, wg *sync.WaitGroup) {
	defer wg.Done()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for j := range jobs {
		url := fmt.Sprintf("%s://%s:%s", j.protocol, j.ip, j.port)
		fqdn := j.subdomain + "." + config.Domain
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Host = fqdn
		req.Header.Set("User-Agent", "VHostGo/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		if baseline.BodyHash != "" {
			hash := sha256.Sum256(bodyBytes)
			bodyHashHex := hex.EncodeToString(hash[:])
			if resp.StatusCode == baseline.Status && bodyHashHex == baseline.BodyHash {
				continue
			}
		}
		results <- Result{
			Subdomain:     j.subdomain,
			IP:            j.ip,
			Protocol:      j.protocol,
			Port:          j.port,
			Status:        resp.StatusCode,
			ContentLength: int64(len(bodyBytes)),
		}
	}
}


// writeOutput and readLines remain unchanged
func writeOutput(config Config, results []Result) {
	if len(results) == 0 {
		fmt.Println("[-] No unique virtual hosts discovered.")
		return
	}
	if config.OutputFormat == "simple" {
		return
	}
	var outputData string
	var err error
	switch config.OutputFormat {
	case "json":
		jsonData, jsonErr := json.MarshalIndent(results, "", "  ")
		if jsonErr != nil {
			err = jsonErr
		} else {
			outputData = string(jsonData)
		}
	case "csv":
		var builder strings.Builder
		builder.WriteString("subdomain,ip,protocol,port,status,content_length\n")
		for _, r := range results {
			builder.WriteString(fmt.Sprintf("%s,%s,%s,%s,%d,%d\n", r.Subdomain, r.IP, r.Protocol, r.Port, r.Status, r.ContentLength))
		}
		outputData = builder.String()
	default:
		fmt.Printf("[-] Unknown output format: %s\n", config.OutputFormat)
		return
	}
	if err != nil {
		fmt.Printf("[-] Error generating output: %v\n", err)
		return
	}
	if config.OutputFile != "" {
		err := os.WriteFile(config.OutputFile, []byte(outputData), 0644)
		if err != nil {
			fmt.Printf("[-] Error writing to output file: %v\n", err)
		} else {
			fmt.Printf("[+] Results saved to %s\n", config.OutputFile)
		}
	} else {
		fmt.Println(outputData)
	}
}
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// saveIPsToFile writes a slice of IP addresses to a file.
func saveIPsToFile(path string, ips []string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, ip := range ips {
		_, err := writer.WriteString(ip + "\n")
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}
