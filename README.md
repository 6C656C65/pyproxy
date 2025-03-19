# 🚀 pyproxy
**pyproxy** is a lightweight, fast, and customizable Python-based web proxy server designed to handle both HTTP and HTTPS traffic efficiently. It can be used for various purposes, including web scraping, traffic monitoring, and content filtering.

## 📑 **Table of Contents**

1. [Features](#-features)
2. [Installation](#-installation)
   - [Install from source](#install-from-source)
3. [Usage](#-usage)
   - [Start the Proxy](#start-the-proxy)
   - [Debug Mode](#debug-mode)
4. [To do](#-to-do)

## ⚡ **Features**

- Support HTTP & HTTPS
- Logging web requests
- HTTP : Domains and URLs blacklist
- HTTPS : Domains and URLs blakclist
- Inspection SSL
- Custom page for 403 Forbidden

## 📦 **Installation**

### Install from source
```bash
git clone https://github.com/6C656C65/pyproxy.git
pip install -r requirements.txt
```

### Install with Docker
```bash
docker pull ghcr.io/6c656c65/pyproxy:latest
docker run -d ghcr.io/6c656c65/pyproxy:latest
```

## 🚀 **Usage**

### Generate CA
If we want to generate a self-signed certificate authority, you can use the following OpenSSL command:
```bash
openssl req -x509 -newkey rsa:4096 -keyout certs/ca/key.pem -out certs/ca/cert.pem -days 365 -nodes
```
Otherwise, upload your CA certificate `./certs/ca/cert.pem` and associated key `./certs/ca/key.pem`.

### Start the proxy
```bash
python3 pyproxy.py
```
The proxy will be available at: `0.0.0.0:8080`.
The access log will be available at `./logs/access.log`.

### Debug Mode
To run the proxy in debug mode, use the `--debug` option:
```bash
python3 pyproxy.py --debug
```

## 🔧 **To do**

- Documentation
- Cancel inspection on bank site
- Support content analysis
- Support distant blacklist / whitelist
- Caching of latest and most searched pages
- Adding ACL
- Proxy authentication
- Benchmark
- Admin mode, statistiques and real time request
- Shortcut
- Custom header
- Remove cert

---