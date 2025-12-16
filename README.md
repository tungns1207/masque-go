# MASQUE-Go (Modified for Traffic Analysis)

This repository is a fork of `quic-go/masque-go` with modifications to support full traffic decryption and analysis, specifically for the initial CONNECT packets on the loopback interface.

## Description of Changes

### The Problem
Previously, the TLS key export mechanism only allowed decryption of the flow between the Proxy (`127.0.0.1:4443`) and the Destination Server. However, to decrypt and analyze the initial **CONNECT packet**, we need to decrypt the traffic on the loopback interface (Client $\leftrightarrow$ Proxy: `127.0.0.1` to `127.0.0.1`), which was missing.

### The Solution
1.  **Dual Key Logging:** Modified `client/main.go` to log TLS keys for **both flows** (Client $\leftrightarrow$ Proxy and Proxy $\leftrightarrow$ Target) into a single `SSLKEYLOGFILE`. This enables full decryption of the handshake and the CONNECT packet in Wireshark.
2.  **Insecure Mode:** Added an `-insecure` flag to bypass certificate verification. This resolves issues where self-signed certificates fail to validate in my computer environment.

---

## Usage

The implementation steps remain the same as in the previous version

### 1. Clone the repository

```bash
git clone https://github.com/tungns1207/masque-go.git
```
### Note: The repository includes a demo .pcap file and a key.log file in the certs directory

**Note:** If you encounter a "certificate not valid" error, you can regenerate the certificates using the following command:

```bash
openssl req -x509 -nodes -days 10950 -newkey rsa:2048 \
    -keyout certs/server.key \
    -out certs/server.crt \
    -config certs/san.cnf \
    -extensions v3_req
```

### 2. Compile the Client and Proxy


```bash
sudo -E go build -o /usr/local/bin/masque-client ./cmd/client &&   sudo -E  go build -o /usr/local/bin/masque-proxy ./cmd/proxy
```

### 3. Set Environment Variables

Set the certificate file and the key log location. This is required for Wireshark to decrypt the traffic.

```bash
export SSL_CERT_FILE=certs/server.crt
export SSLKEYLOGFILE=certs/keys.log
```

### 4. Start the Proxy

Run the proxy on port 4443:

```bash
masque-proxy -b :4443 -c certs/server.crt -k certs/server.key -t "https://127.0.0.1:4443/masque?h={target_host}&p={target_port}"
```

### 5. Start the Client

Run the client. Use the `-insecure` flag to skip certificate verification if using self-signed certs:

```bash
masque-client -insecure -t "https://127.0.0.1:4443/masque?h={target_host}&p={target_port}" https://cloudflare-quic.com:443
```
