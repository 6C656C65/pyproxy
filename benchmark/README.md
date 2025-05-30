# 🏎️ Benchmark for pyproxy

This benchmarking tool is designed to measure the performance of **pyproxy** in handling HTTP and HTTPS requests. It allows you to compare the average, maximum, and minimum request times both with and without the proxy.

---

## 📦 **Installation**

### Install dependencies
Before running the benchmark, you need to install the required dependencies. You can do so by running the following command:
```bash
pip install -r benchmark/requirements.txt
```

---

## 🚀 **Usage**

### Start the Proxy
Before running the benchmark, ensure that **pyproxy** is running. Start the proxy by running:
```bash
python3 -m pyproxy.pyproxy
```
The proxy will be available at `0.0.0.0:8080`.

### Run the benchmark
Once the proxy is up and running, execute the following command from the root of the project to start the benchmark:
```bash
python3 benchmark/benchmark.py --target-file benchmark/urls.txt
```

This will run the benchmark using the URLs listed in `benchmark/urls.txt` and generate a report on the request times, comparing the proxy performance (with and without the proxy).

### Customizing the URLs and Requests

- You can modify the `benchmark/urls.txt` file to add multiple URLs that you want to benchmark. Each line should contain a URL.
  
- Alternatively, you can test a single URL by using the `--target-url` argument. For example:
  ```bash
  python3 benchmark/benchmark.py --target-url http://example.com
  ```

- You can also change the number of requests made during the benchmark using the `--num-requests` argument. By default, it tests 100 requests per URL, but you can adjust it like this:
  ```bash
  python3 benchmark/benchmark.py --target-file benchmark/urls.txt --num-requests 50
  ```
  This will test 50 requests per URL instead of the default 10.

---

## 📊 **Benchmark Results**

The benchmarking script will produce a table comparing the average, maximum, and minimum request times for each URL, as well as a breakdown into the following columns:

- **With Proxy**:
  - **Avg**: Average request time with the proxy.
  - **Max**: Maximum request time with the proxy.
  - **Min**: Minimum request time with the proxy.
  
- **Without Proxy**:
  - **Avg**: Average request time without the proxy.
  - **Max**: Maximum request time without the proxy.
  - **Min**: Minimum request time without the proxy.

The detailed report will be available in the `outputs` directory as a file named `benchmark_combined_report_<timestamp>.html`. You can open this HTML file in a browser to view the results.

## 📈 **Example Benchmark Results**

### Global Proxy Performance Summary

| **Metric**                          | **Value**           |
|--------------------------------------|--------------------|
| Global average without proxy         | 0.341067 seconds   |
| Global average with proxy            | 0.414619 seconds   |
| Impact (Slowdown)                    | 21.57%             |

### Benchmark Results Summary

| **URL**               | **Avg (s)** | **Min (s)** | **Max (s)** | **Avg with Proxy (s)** | **Min with Proxy (s)** | **Max with Proxy (s)** |
|-----------------------|-------------|-------------|-------------|-------------------------|-------------------------|-------------------------|
| `http://example.com`  | 0.24766     | 0.19376     | 0.30262     | 0.27064                 | 0.19926                 | 0.30419                 |
| `https://example.com` | 0.43447     | 0.33968     | 0.48372     | 0.55860                 | 0.41271                 | 0.67175                 |

---

### Example Reports 

Example reports can be found in the following files:
- [Interactive Report Example](outputs/benchmark_combined_interactive_example.html)
- [Report Example](outputs/benchmark_combined_report_example.html)

These files contain example benchmark results and interactive graphs.

---