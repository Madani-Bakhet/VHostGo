# VHostGo

```
__     ___   _           _    ____       
\ \   / / | | | ___  ___| |_ / ___| ___  
 \ \ / /| |_| |/ _ \/ __| __| |  _ / _ \ 
  \ V / |  _  | (_) \__ \ |_| |_| | (_) |
   \_/  |_| |_|\___/|___/\__|\____|\___/ 
                                         
```

VHostGo is a fast, concurrent, and flexible virtual host scanner written in Go. It's designed to help security testers and system administrators discover web applications hosted on a single IP address by manipulating the HTTP `Host` header.

## Features

- **Fast Concurrent Scanning:** Utilizes Go's native goroutines to perform hundreds of checks simultaneously.
    
- **Smart Baseline Filtering:** Automatically sends a request with a random subdomain to establish a baseline for "Not Found" responses, filtering out wildcard/default server pages and reducing false positives.
    
- **Flexible Target Specification:** Scan a domain via DNS resolution or target specific IP addresses directly.
    
- **Recursive IP Discovery:** Can optionally resolve each generated subdomain (`sub.example.com`) to uncover additional IP addresses associated with the target.
    
- **Customizable Scans:** Specify custom ports, protocols (HTTP/HTTPS), concurrency levels, and timeouts.
    
- **Multiple Output Formats:** Supports simple console output, CSV, and JSON for easy integration with other tools.
    
- **Save Discoveries:** Option to save discovered IP addresses to a file for use in chained workflows.
    

## Installation

There are two ways to install and use VHostGo.

#### Option 1: Install with `go install` (Recommended)

This is the easiest method. It will download, compile, and install the `VHostGo` binary in your `$GOPATH/bin` directory.

content_copy

sh

```sh
go install github.com/[YOUR-GITHUB]/VHostGo@latest
```

Make sure your `$GOPATH/bin` directory is in your system's `PATH` to run the tool from any location.

#### Option 2: Build from Source

This method gives you more control and is useful for development.

content_copy

sh

```sh
# 1. Clone the repository
git clone https://github.com/[YOUR-GITHUB]/VHostGo.git

# 2. Navigate into the project directory
cd VHostGo

# 3. Build the executable
go build -o VHostGo

# 4. (Optional) Move the binary to a directory in your PATH
# For Linux/macOS
sudo mv VHostGo /usr/local/bin/

# For Windows, you can add the directory to your Path environment variable
```

## Usage

VHostGo requires a target domain (for the `Host` header) and a wordlist of subdomains to test.

content_copy

sh

```sh
VHostGo -d <domain> -w <wordlist> [options]
```

### Options

|Short Flag|Long Flag|Description|
|---|---|---|
|**-d**|`--domain`|Target domain for the `Host` header (e.g., example.com) (required)|
|**-w**|`--wordlist`|Path to the subdomain wordlist (required)|
|**-i**|`--ip`|Comma-separated list of specific IP addresses to scan (overrides DNS resolution)|
|**-r**|`--resolve-new`|Enable resolution of each generated subdomain to discover more IPs|
|**-n**|`--num-ips`|Number of initial IPs to scan per domain (0 for all, default 0)|
|**-s**|`--save-ips`|File to save the discovered IP addresses to|
|**-c**|`--concurrency`|Number of concurrent scanning threads to use (default 50)|
|**-t**|`--timeout`|Timeout in seconds for each web request (default 5)|
|**-p**|`--protocols`|Comma-separated list of protocols to use (default "http,https")|
|**-P**|`--ports`|Comma-separated list of ports to scan (default "80,443")|
|**-f**|`--output-format`|Output format (simple, csv, json) (default "simple")|
|**-o**|`--output-file`|File to save the scan results to|
|**-h**|`--help`|Show the help message|

content_copy 

download

## Examples

#### Basic Scan

Scan `example.com` on ports 80 and 443 using a list of subdomains.

content_copy

sh

```sh
./VHostGo -d example.com -w subdomains.txt
```

#### Advanced Scan

Scan a domain with high concurrency, recursively discover new IPs, check common web ports, and save the output as a JSON file.

content_copy

sh

```sh
./VHostGo -d example.com -w subdomains.txt -c 150 -r -P 80,443,8000,8080,8443 -f json -o results.json
```

#### Targeting a Specific IP Address

Scan a specific internal server to find what applications it's hosting. The `-d` flag is still used for the `Host` header.

content_copy

sh

```sh
./VHostGo -d internal.app -w wordlist.txt -i 10.0.0.5
```

#### Discovering and Saving IPs

Find all IPs associated with a domain and its subdomains, then save them to a file for later use with other tools like `nmap`.

content_copy

sh

```sh
./VHostGo -d example.com -w common-subs.txt -r -s discovered-ips.txt
```