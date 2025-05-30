"""
This module provides a set of functions to benchmark the performance of a proxy server
by comparing the response times for HTTP requests sent with and without the use of a proxy.
"""

import time
import argparse
import sys
import os
from datetime import datetime
import pandas as pd
from utils.req import send_request_with_proxy, send_request_without_proxy
from utils.html import create_combined_html_report


def benchmark(url: str, proxy: str, num_requests: int) -> tuple:
    """
    Benchmarks the performance of sending requests to the specified$
    URL with and without using a proxy. It sends multiple requests and
    records the time taken for each.

    Args:
        url (str): The URL to benchmark.
        proxy (str): The proxy URL to use for the benchmark.
        num_requests (int): The number of requests to send.

    Returns:
        tuple: A tuple containing:
            - A dictionary with statistics (average, min, max) for requests without and with proxy.
            - A pandas DataFrame containing the times for each request without and with proxy.
    """
    times_without_proxy = []
    times_with_proxy = []

    print(f"Sending requests without proxy for {url}...")
    for i in range(num_requests):
        times_without_proxy.append(send_request_without_proxy(url))
        sys.stdout.write(f"\rRequests sent without proxy: {i + 1}/{num_requests}")
        sys.stdout.flush()
        time.sleep(0.1)

    print(f"\nSending requests with proxy for {url}...")
    for i in range(num_requests):
        times_with_proxy.append(send_request_with_proxy(url, proxy))
        sys.stdout.write(f"\rRequests sent with proxy: {i + 1}/{num_requests}")
        sys.stdout.flush()
        time.sleep(0.1)

    print("\n")

    stats = {
        "avg_without_proxy": sum(times_without_proxy) / len(times_without_proxy),
        "min_without_proxy": min(times_without_proxy),
        "max_without_proxy": max(times_without_proxy),
        "avg_with_proxy": sum(times_with_proxy) / len(times_with_proxy),
        "min_with_proxy": min(times_with_proxy),
        "max_with_proxy": max(times_with_proxy),
    }

    results = pd.DataFrame(
        {
            "Request Number": range(1, num_requests + 1),
            "Without Proxy": times_without_proxy,
            "With Proxy": times_with_proxy,
        }
    )

    return stats, results


def main() -> None:
    """
    Main function to parse command-line arguments, run benchmarks, and generate the report.
    It either benchmarks a single URL or a list of URLs from a file.

    Returns:
        None
    """
    parser = argparse.ArgumentParser(description="Proxy performance benchmark.")
    parser.add_argument(
        "--proxy-url",
        type=str,
        default="http://localhost:8080",
        help="The proxy URL to use",
    )
    parser.add_argument(
        "--target-url",
        type=str,
        help="A single URL to test (e.g., http://example.com)",
    )
    parser.add_argument(
        "--target-file",
        type=str,
        help="A file containing a list of URLs to test",
    )
    parser.add_argument(
        "--num-requests",
        type=int,
        default=10,
        help="Number of requests to send (default: 10)",
    )
    parser.add_argument(
        "--output-dir", type=str, default="benchmark/outputs", help="Output directory"
    )
    args = parser.parse_args()

    if not args.target_url and not args.target_file:
        print("Error: you must provide either --target-url or --target-file.")
        sys.exit(1)

    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    all_results = {}

    if args.target_file:
        if not os.path.exists(args.target_file):
            print(f"Error: the file {args.target_file} does not exist.")
            sys.exit(1)

        with open(args.target_file, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]

        for url in urls:
            print(f"\nBenchmarking for {url}")
            stats, results = benchmark(url, args.proxy_url, args.num_requests)
            all_results[url] = (stats, results)
    else:
        stats, results = benchmark(args.target_url, args.proxy_url, args.num_requests)
        all_results[args.target_url] = (stats, results)

    avg_without_proxy_list = []
    avg_with_proxy_list = []

    for stats, _ in all_results.values():
        avg_without_proxy_list.append(stats["avg_without_proxy"])
        avg_with_proxy_list.append(stats["avg_with_proxy"])

    global_avg_without_proxy = sum(avg_without_proxy_list) / len(avg_without_proxy_list)
    global_avg_with_proxy = sum(avg_with_proxy_list) / len(avg_with_proxy_list)

    percentage_change = (
        (global_avg_with_proxy - global_avg_without_proxy) / global_avg_without_proxy
    ) * 100

    print(f"Global average without proxy: {global_avg_without_proxy:.6f} seconds")
    print(f"Global average with proxy: {global_avg_with_proxy:.6f} seconds")
    print(
        f"Impact: {'Improvement' if percentage_change < 0 else 'Slowdown'} of "
        f"{abs(percentage_change):.2f}%"
    )

    create_combined_html_report(
        all_results,
        global_avg_without_proxy,
        global_avg_with_proxy,
        percentage_change,
        args.output_dir,
        timestamp,
    )


if __name__ == "__main__":
    main()
