package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
	"vhost-scanner/scanner"
)

// ASCII Art Banner
const banner = `
__     ___   _           _    ____       
\ \   / / | | | ___  ___| |_ / ___| ___  
 \ \ / /| |_| |/ _ \/ __| __| |  _ / _ \ 
  \ V / |  _  | (_) \__ \ |_| |_| | (_) |
   \_/  |_| |_|\___/|___/\__|\____|\___/ 
                                         
`
// printCustomHelp now only displays the usage and options, not the banner.
func printCustomHelp() {
	fmt.Println("\nUsage: VHostGo -d <domain> -w <path> [options]")
	fmt.Println("\nOptions:")
	fmt.Println("  Target Specification:")
	fmt.Println("    -d, --domain string      Target domain for the Host header (e.g., example.com) (required)")
	fmt.Println("    -w, --wordlist string    Path to the subdomain wordlist (required)")
	fmt.Println("    -i, --ip string          Comma-separated list of specific IP addresses to scan (overrides DNS resolution)")
	fmt.Println()
	fmt.Println("  Discovery & IP Management:")
	fmt.Println("    -r, --resolve-new        Enable resolution of each generated subdomain to discover more IPs")
	fmt.Println("    -n, --num-ips int        Number of initial IPs to scan per domain (0 for all, default 0)")
	fmt.Println("    -s, --save-ips file      File to save the discovered IP addresses to")
	fmt.Println()
	fmt.Println("  Scan Configuration:")
	fmt.Println("    -c, --concurrency int    Number of concurrent scanning threads to use (default 50)")
	fmt.Println("    -t, --timeout int        Timeout in seconds for each web request (default 5)")
	fmt.Println("    -p, --protocols string   Comma-separated list of protocols to use (default \"http,https\")")
	fmt.Println("    -P, --ports string       Comma-separated list of ports to scan (default \"80,443\")")
	fmt.Println()
	fmt.Println("  Output:")
	fmt.Println("    -f, --output-format string  Output format (simple, csv, json) (default \"simple\")")
	fmt.Println("    -o, --output-file file      File to save the scan results to")
	fmt.Println()
	fmt.Println("  Help:")
	fmt.Println("    -h, --help               Show this help message")
	fmt.Println()
}


func main() {
	// --- Print Banner and Creator Info on EVERY run ---
	fmt.Println(banner)
	fmt.Println("             A Go-based Virtual Host Scanner")
	fmt.Println("      Creator: [Madani Bakhet/RalphXM1] (https://github.com/Madani-Bakhet)")
	fmt.Println("      Tool Link: https://github.com/Madani-Bakhet/VHostGo")
	fmt.Println()

	// --- Define command-line flags ---
	var domain, wordlistPath, outputFormat, outputFile, protocolsStr, portsStr, ips, saveIPsFile string
	var numIPs, timeout, concurrency int
	var resolveNew, showHelp bool

	// (Flag definitions remain the same as before)
	flag.StringVar(&domain, "domain", "", "")
	flag.StringVar(&domain, "d", "", "")
	flag.StringVar(&wordlistPath, "wordlist", "", "")
	flag.StringVar(&wordlistPath, "w", "", "")
	flag.StringVar(&ips, "ip", "", "")
	flag.StringVar(&ips, "i", "", "")
	flag.BoolVar(&resolveNew, "resolve-new", false, "")
	flag.BoolVar(&resolveNew, "r", false, "")
	flag.IntVar(&numIPs, "num-ips", 0, "")
	flag.IntVar(&numIPs, "n", 0, "")
	flag.StringVar(&saveIPsFile, "save-ips", "", "")
	flag.StringVar(&saveIPsFile, "s", "", "")
	flag.IntVar(&concurrency, "concurrency", 50, "")
	flag.IntVar(&concurrency, "c", 50, "")
	flag.IntVar(&timeout, "timeout", 5, "")
	flag.IntVar(&timeout, "t", 5, "")
	flag.StringVar(&protocolsStr, "protocols", "http,https", "")
	flag.StringVar(&protocolsStr, "p", "http,https", "")
	flag.StringVar(&portsStr, "ports", "80,443", "")
	flag.StringVar(&portsStr, "P", "80,443", "")
	flag.StringVar(&outputFormat, "output-format", "simple", "")
	flag.StringVar(&outputFormat, "f", "simple", "")
	flag.StringVar(&outputFile, "output-file", "", "")
	flag.StringVar(&outputFile, "o", "", "")
	flag.BoolVar(&showHelp, "help", false, "")
	flag.BoolVar(&showHelp, "h", false, "")
	
	flag.Usage = func() { printCustomHelp() }
	flag.Parse()

	if showHelp {
		// The banner is already printed, so we just show the help text.
		printCustomHelp()
		os.Exit(0)
	}

	if domain == "" || wordlistPath == "" {
		fmt.Println("[-] Error: --domain (-d) and --wordlist (-w) are required.")
		fmt.Println("[-] Use --help or -h for usage details.")
		os.Exit(1)
	}

	protocols := strings.Split(protocolsStr, ",")
	ports := strings.Split(portsStr, ",")

	config := scanner.Config{
		Domain:       domain,
		WordlistPath: wordlistPath,
		IPs:          ips,
		SaveIPsFile:  saveIPsFile,
		OutputFormat: outputFormat,
		OutputFile:   outputFile,
		NumIPs:       numIPs,
		Protocols:    protocols,
		Ports:        ports,
		Timeout:      time.Duration(timeout) * time.Second,
		Concurrency:  concurrency,
		ResolveNew:   resolveNew,
	}

	scanner.Run(config)
}
