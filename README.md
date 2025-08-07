# CyberSentinel

CyberSentinel is a powerful C++ cybersecurity toolkit offering key features for network reconnaissance and analysis, including:

- Fast TCP port scanning
- Live packet sniffing using `libpcap`
- Basic OS fingerprinting based on TTL values

## Requirements

- C++17
- libpcap (Linux or WSL on Windows)
- Root privileges (for sniffing)

## Build

```bash
g++ CyberSentinel.cpp -o CyberSentinel -lpcap -pthread
