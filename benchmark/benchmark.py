"""
This module provides a set of functions to benchmark the performance of a proxy server 
by comparing the response times for HTTP requests sent with and without the use of a proxy.
"""

import time
import argparse
import sys
import os
from datetime import datetime
import plotly.graph_objects as go
import pandas as pd
from utils.req import send_request_with_proxy, send_request_without_proxy

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

    results = pd.DataFrame({
        'Request Number': range(1, num_requests + 1),
        'Without Proxy': times_without_proxy,
        'With Proxy': times_with_proxy
    })

    return stats, results

def generate_html_section_for_url(url: str, stats: dict) -> str:
    """
    Generates the HTML section for a specific URL with benchmark statistics.
    
    Args:
        url (str): The URL being tested.
        stats (dict): The statistics for the URL.

    Returns:
        str: The HTML section as a string.
    """
    section = f"""
    <h2>Results for {url}</h2>
    <h3>Without proxy</h3>
    <p>Average: {stats['avg_without_proxy']:.5f} seconds</p>
    <p>Min: {stats['min_without_proxy']:.5f} seconds</p>
    <p>Max: {stats['max_without_proxy']:.5f} seconds</p>

    <h3>With proxy</h3>
    <p>Average: {stats['avg_with_proxy']:.5f} seconds</p>
    <p>Min: {stats['min_with_proxy']:.5f} seconds</p>
    <p>Max: {stats['max_with_proxy']:.5f} seconds</p>
    <hr>
    """
    return section

def prepare_filenames(output_dir: str, timestamp: str) -> dict:
    """
    Prepares the filenames for the report and plotly files.
    
    Args:
        output_dir (str): The directory to save the report in.
        timestamp (str): The timestamp to use in filenames.
        
    Returns:
        dict: A dictionary containing the plotly and html file paths.
    """
    output_dir = os.path.normpath(output_dir)

    plotly_filename = f"benchmark_combined_interactive_{timestamp}.html"
    html_filename = f"benchmark_combined_report_{timestamp}.html"

    plotly_filepath = os.path.join(output_dir, plotly_filename)
    html_filepath = os.path.join(output_dir, html_filename)

    return {
        "plotly": plotly_filepath,
        "html": html_filepath
    }

def create_combined_html_report(all_results: dict, avg_without_proxy: float, avg_with_proxy: float,
                                percentage_change: float, output_dir: str, timestamp: str) -> None:
    """
    Generates an HTML report with the benchmark results, including graphs and statistics. 
    Saves the report to the specified output directory.

    Args:
        all_results (dict): A dictionary containing the results for each URL.
        avg_without_proxy (float): The average time for requests without a proxy.
        avg_with_proxy (float): The average time for requests with a proxy.
        percentage_change (float): The percentage change in performance
                    between requests with and without a proxy.
        output_dir (str): The directory to save the report in.
        timestamp (str): The timestamp to use in filenames.
        
    Returns:
        None
    """
    fig = go.Figure()
    html_sections = ""

    filenames = prepare_filenames(output_dir, timestamp)
    print(filenames)

    for url, (stats, results) in all_results.items():
        fig.add_trace(go.Scatter(x=results['Request Number'], y=results['Without Proxy'],
                                 mode='lines+markers', name=f'Without Proxy - {url}'))
        fig.add_trace(go.Scatter(x=results['Request Number'], y=results['With Proxy'],
                                 mode='lines+markers', name=f'With Proxy - {url}'))

        html_sections += generate_html_section_for_url(url, stats)

    fig.update_layout(title="Response Time per Request (All URLs)",
                      xaxis_title="Request Number",
                      yaxis_title="Response Time (seconds)")

    fig.write_html(filenames["plotly"])

    plotly_filename = os.path.basename(filenames["plotly"])

    html_content = f"""
    <html>
    <head><title>Proxy Performance Benchmark</title></head>
    <body>
        <h1>Global Proxy Performance Benchmark</h1>
        
        <!-- Global performance summary at the top -->
        <h2>Global Performance Summary</h2>
        <p><strong>Global average without proxy: </strong>{avg_without_proxy:.6f} seconds</p>
        <p><strong>Global average with proxy: </strong>{avg_with_proxy:.6f} seconds</p>
        <p><strong>Impact: </strong>{'Improvement' if percentage_change < 0 else 'Slowdown'} of {abs(percentage_change):.2f}%</p>
        
        {html_sections}
        <h2>Graphs</h2>
        <p>Global interactive response time graph</p>
        <iframe src="{plotly_filename}" width="100%" height="600"></iframe>
    </body>
    </html>
    """

    with open(filenames["html"], "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"\nThe combined report has been generated at '{filenames['html']}'.")

def main() -> None:
    """
    Main function to parse command-line arguments, run benchmarks, and generate the report. 
    It either benchmarks a single URL or a list of URLs from a file.
    
    Returns:
        None
    """
    parser = argparse.ArgumentParser(description="Proxy performance benchmark.")
    parser.add_argument(
        '--proxy-url',
        type=str,
        default="http://localhost:8080",
        help="The proxy URL to use"
    )
    parser.add_argument(
        '--target-url',
        type=str,
        help="A single URL to test (e.g., http://example.com)"
    )
    parser.add_argument(
        '--target-file',
        type=str,
        help="A file containing a list of URLs to test"
    )
    parser.add_argument(
        '--num-requests',
        type=int,
        default=10,
        help="Number of requests to send (default: 10)"
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default="benchmark/outputs",
        help="Output directory"
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

        with open(args.target_file, 'r', encoding="utf-8") as f:
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
        avg_without_proxy_list.append(stats['avg_without_proxy'])
        avg_with_proxy_list.append(stats['avg_with_proxy'])

    global_avg_without_proxy = sum(avg_without_proxy_list) / len(avg_without_proxy_list)
    global_avg_with_proxy = sum(avg_with_proxy_list) / len(avg_with_proxy_list)

    percentage_change = (
        (global_avg_with_proxy - global_avg_without_proxy) /
        global_avg_without_proxy
    ) * 100

    print(f"Global average without proxy: {global_avg_without_proxy:.6f} seconds")
    print(f"Global average with proxy: {global_avg_with_proxy:.6f} seconds")
    print(f"Impact: {'Improvement' if percentage_change < 0 else 'Slowdown'} of "
          f"{abs(percentage_change):.2f}%")

    create_combined_html_report(
        all_results, global_avg_without_proxy, global_avg_with_proxy,
        percentage_change, args.output_dir, timestamp
    )

if __name__ == "__main__":
    main()
