<div align="center">
  <h1>pyproxy</h1>
</div>


**pyproxy** is a lightweight, fast, and customizable Python-based web proxy server designed to handle both HTTP and HTTPS traffic efficiently. It can be used for various purposes, including web scraping, traffic monitoring, and content filtering.

<p align="center">
  <img src="https://img.shields.io/github/license/6C656C65/pyproxy?style=for-the-badge">
  <img src="https://img.shields.io/github/issues/6C656C65/pyproxy?style=for-the-badge">
  <img src="https://img.shields.io/github/issues-closed/6C656C65/pyproxy?style=for-the-badge">
  <br>
  <img src="https://img.shields.io/github/forks/6C656C65/pyproxy?style=for-the-badge">
  <img src="https://img.shields.io/github/stars/6C656C65/pyproxy?style=for-the-badge">
  <img src="https://img.shields.io/github/commit-activity/w/6C656C65/pyproxy?style=for-the-badge">
  <img src="https://img.shields.io/github/contributors/6C656C65/pyproxy?style=for-the-badge">
  <br>
  <img src="https://img.shields.io/github/actions/workflow/status/6C656C65/pyproxy/code-scan.yml?label=Scan&style=for-the-badge">
  <img src="https://img.shields.io/github/actions/workflow/status/6C656C65/pyproxy/unittest.yml?label=Tests&style=for-the-badge">
  <img src="https://img.shields.io/github/actions/workflow/status/6C656C65/pyproxy/docker-images.yml?label=Delivery&style=for-the-badge">
</p>

---

## ⚡ **Features**

| Feature                                      | Supported |
|----------------------------------------------|-----------|
| HTTP & HTTPS                                 | ✅        |
| Web request logging                          | ✅        |
| Domain & URL blacklist                       | ✅        |
| SSL inspection                               | ✅        |
| Custom 403 Forbidden page                    | ✅        |
| Remote (HTTP) blacklist support              | ✅        |
| Shortcut support                             | ✅        |
| Disable inspection for banking websites      | ✅        |
| Custom headers                               | ✅        |
| Web interface monitoring                     | ✅        |
| Lightweight Docker image                     | ✅        |
| Proxy chaining (multi-proxy forwarding)      | ✅        |
| IP whitelist with subnet support             | ✅        |

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

### Start the proxy
```bash
python3 -m pyproxy.pyproxy
```
The proxy will be available at: `0.0.0.0:8080`.
The access log will be available at `./logs/access.log`.

## 📚 **Documentation**
If you encounter any problems, or if you want to use the program in a particular way, I advise you to read the [documentation](https://github.com/6C656C65/pyproxy/wiki).

## 🔧 **To do**

- Support content analysis
- Caching of latest and most searched pages

## 🏎️ **Benchmark**

If you're interested in benchmarking the performance of the proxy or comparing request times with and without a proxy, please refer to the [Benchmark README](benchmark/README.md) for detailed instructions on how to run the benchmarking tests and generate reports.

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 **Contributing**

Contributions are welcome and appreciated! If you'd like to improve this project, feel free to fork the repository and submit a pull request. Whether it's fixing bugs, adding new features, improving documentation, or suggesting enhancements, every bit helps. Please make sure to follow the coding standards and test your changes before submitting. Let's build something great together!

## 📦 Deployment with Ansible

If you want to deploy **pyproxy** automatically to remote servers (via source or Docker), an official [Ansible role](https://github.com/6C656C65/pyproxy_ansible) is available:

* 🔧 Install from source or run as a Docker container
* 📁 Supports customization of ports, versions, and paths
* 🚀 Easily integrable into your infrastructure or CI/CD pipelines

👉 Check out the [ansible-role-pyproxy](https://github.com/6C656C65/pyproxy_ansible) repository for more details and usage instructions.

---