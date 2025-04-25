# 🚀 pyproxy
**pyproxy** is a lightweight, fast, and customizable Python-based web proxy server designed to handle both HTTP and HTTPS traffic efficiently. It can be used for various purposes, including web scraping, traffic monitoring, and content filtering.

---

![GitHub Release](https://img.shields.io/github/v/release/6C656C65/pyproxy)
![GitHub License](https://img.shields.io/github/license/6C656C65/pyproxy)

![GitHub forks](https://img.shields.io/github/forks/6C656C65/pyproxy)
![GitHub stars](https://img.shields.io/github/stars/6C656C65/pyproxy)
![GitHub issues open](https://img.shields.io/issues/6C656C65/pyproxy)
![GitHub issues closed](https://img.shields.io/issues-closed/6C656C65/pyproxy)

![GitHub Actions lint](https://img.shields.io/github/actions/workflow/status/6C656C65/pyproxy/pylint.yml)
![GitHub Actions test](https://img.shields.io/github/actions/workflow/status/6C656C65/pyproxy/unittest.yml)
![GitHub Actions push](https://img.shields.io/github/actions/workflow/status/6C656C65/pyproxy/docker-images.yml)

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
- Support distant (http) blacklist
- Shortcuts
- Cancel inspection on bank site
- Custom header
- Web interface monitoring (actives connections, processes status)
- Docker image slim wihtout (moniting, custom header & shortcuts)

## 📦 **Installation**

### Install from source
```bash
git clone https://github.com/6C656C65/pyproxy.git
cd pyproxy
pip install -r requirements.txt
```

### Install with Docker
```bash
docker pull ghcr.io/6c656c65/pyproxy:latest
docker run -d ghcr.io/6c656c65/pyproxy:latest
```
You can use slim images by adding `-slim` to the end of the tags

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

## 📚 **Documentation**
If you encounter any problems, or if you want to use the program in a particular way, I advise you to read the [documentation](https://github.com/6C656C65/pyproxy/wiki).

## 🔧 **To do**

- Support content analysis
- Caching of latest and most searched pages
- Adding ACL
- Proxy authentication
- Benchmark
- Fix HSTS

---