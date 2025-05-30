"""
pyproxy.monitoring.web.py

This module defines a monitoring system for the ProxyServer that provides
information about the server's processes, threads, active connections, and
subprocesses. It includes an HTTP server implemented with Flask to expose
monitoring endpoints for the proxy server.
"""

import os
import threading
import multiprocessing
import logging
from datetime import datetime
from typing import List, Dict, Union
from flask import Flask, jsonify, render_template
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash, generate_password_hash
import psutil


def start_flask_server(proxy_server, flask_port, flask_pass, debug) -> None:
    """
    Starts the Flask server for monitoring the ProxyServer. It creates and
    runs an HTTP server that exposes the proxy server's status, including
    process and thread details, subprocess statuses, and active connections.

    Args:
        proxy_server (ProxyServer): The ProxyServer instance to monitor.

    The server will expose two routes:
        - '/' : Renders a simple index page.
        - '/monitoring' : Returns a JSON response with the monitoring data.
    """

    class ProxyMonitor:
        """
        Monitors the status of the ProxyServer, including process, thread,
        and subprocess information, as well as active client connections.

        Args:
            proxy_server (ProxyServer): The ProxyServer instance to monitor.
        """

        def __init__(self, proxy_server):
            self.proxy_server = proxy_server

        def get_process_info(
            self,
        ) -> Dict[str, Union[int, str, List[Dict[str, Union[int, str]]]]]:
            """
            Retrieves overall process information for the ProxyServer,
            including the PID, name, status, and details about threads,
            subprocesses, and active connections.

            Returns:
                dict: A dictionary containing the process information.
            """
            process_info = {
                "pid": os.getpid(),
                "name": "ProxyServer",
                "status": "running",
                "start_time": datetime.fromtimestamp(
                    psutil.Process(os.getpid()).create_time()
                ).strftime("%Y-%m-%d %H:%M:%S"),
                "threads": self.get_threads_info(),
                "subprocesses": self.get_subprocesses_info(),
                "active_connections": self.get_active_connections(),
            }
            return process_info

        def get_threads_info(self) -> List[Dict[str, Union[int, str]]]:
            """
            Retrieves information about the threads running in the ProxyServer.

            Returns:
                list: A list of dictionaries, each containing information
                      about a thread.
            """
            threads_info = []
            for thread in threading.enumerate():
                threads_info.append(
                    {
                        "thread_id": thread.ident,
                        "name": thread.name,
                        "status": self.get_thread_status(thread),
                    }
                )
            return threads_info

        def get_thread_status(self, thread: threading.Thread) -> str:
            """
            Gets the status of a given thread.

            Args:
                thread (threading.Thread): The thread whose status is to be retrieved.

            Returns:
                str: The status of the thread ('running', 'terminated', or 'unknown').
            """
            try:
                if thread.is_alive():
                    return "running"
                return "terminated"
            except AttributeError:
                return "unknown"

        def get_subprocesses_info(
            self,
        ) -> Dict[str, Dict[str, Union[str, List[Dict[str, Union[int, str]]]]]]:
            """
            Retrieves the status of the ProxyServer's subprocesses, including
            filtering, shortcuts, cancel inspection, and custom header processes.

            Returns:
                dict: A dictionary containing subprocess statuses.
            """
            subprocesses_info = {}

            subprocesses = {
                "filter": self.proxy_server.filter_proc,
                "shortcuts": self.proxy_server.shortcuts_proc,
                "cancel_inspect": self.proxy_server.cancel_inspect_proc,
                "custom_header": self.proxy_server.custom_header_proc,
            }

            for name, process in subprocesses.items():
                if process is not None and process.is_alive():
                    subprocesses_info[name] = self.get_subprocess_status(process, name)
            return subprocesses_info

        def get_subprocess_status(
            self, process: multiprocessing.Process, name: str
        ) -> Dict[str, Union[str, None, List[Dict[str, Union[int, str]]]]]:
            """
            Retrieves the status of a subprocess.

            Args:
                process (multiprocessing.Process): The subprocess to check.
                name (str): The name of the subprocess.

            Returns:
                dict: A dictionary containing the subprocess status.
            """
            if process is None:
                return {"status": "not started", "name": name, "threads": []}
            try:
                status = "running" if process.is_alive() else "terminated"
                threads_info = self.get_subprocess_threads_info(process)
            except AttributeError:
                status = "terminated"
                threads_info = []
            return {
                "pid": process.pid if hasattr(process, "pid") else None,
                "status": status,
                "name": name,
                "threads": threads_info,
            }

        def get_subprocess_threads_info(
            self, process: multiprocessing.Process
        ) -> List[Dict[str, Union[int, str]]]:
            """
            Retrieves the threads associated with a subprocess.

            Args:
                process (multiprocessing.Process): The subprocess to check.

            Returns:
                list: A list of dictionaries containing thread information.
            """
            threads_info = []
            try:
                for proc_thread in psutil.Process(process.pid).threads():
                    threads_info.append(
                        {
                            "thread_id": proc_thread.id,
                            "name": f"Thread-{proc_thread.id}",
                            "status": self.get_thread_status_by_pid(proc_thread.id),
                        }
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            return threads_info

        def get_thread_status_by_pid(self, thread_id: int) -> str:
            """
            Attempts to retrieve the status of a thread by its PID.

            Args:
                thread_id (int): The thread's ID.

            Returns:
                str: The status of the thread ('running' or 'terminated').
            """
            try:
                process = psutil.Process(thread_id)
                if process.is_running():
                    return "running"
                return "terminated"
            except psutil.NoSuchProcess:
                return "terminated"

        def get_active_connections(self) -> List[Dict[str, Union[int, Dict]]]:
            """
            Retrieves information about the active client connections to the ProxyServer.

            Returns:
                list: A list of dictionaries containing information about active connections.
            """
            return [
                {"thread_id": thread_id, **conn}
                for thread_id, conn in self.proxy_server.active_connections.items()
            ]

    auth = HTTPBasicAuth()

    users = {"admin": generate_password_hash(flask_pass)}

    @auth.verify_password
    def verify_password(username, password):
        if username in users and check_password_hash(users.get(username), password):
            return username
        return None

    app = Flask(__name__, static_folder="static")
    if not debug:
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.ERROR)

    @app.route("/")
    @auth.login_required
    def index():
        """
        Renders the index page for the Flask application.

        Returns:
            str: The rendered HTML content of the index page.
        """
        return render_template("index.html")

    @app.route("/monitoring", methods=["GET"])
    @auth.login_required
    def monitoring():
        """
        Returns the monitoring data for the ProxyServer in JSON format.

        Returns:
            Response: A JSON response containing the server's process information.
        """
        monitor = ProxyMonitor(proxy_server)
        return jsonify(monitor.get_process_info())

    @app.route("/config", methods=["GET"])
    @auth.login_required
    def config():
        config_data = {
            "host": proxy_server.host_port[0],
            "port": proxy_server.host_port[1],
            "debug": proxy_server.debug,
            "html_403": proxy_server.html_403,
            "logger_config": (
                proxy_server.logger_config.to_dict()
                if proxy_server.logger_config
                else None
            ),
            "filter_config": (
                proxy_server.filter_config.to_dict()
                if proxy_server.filter_config
                else None
            ),
            "ssl_config": (
                proxy_server.ssl_config.to_dict() if proxy_server.ssl_config else None
            ),
            "flask_port": proxy_server.flask_port,
        }
        return jsonify(config_data)

    app.run(host="0.0.0.0", port=flask_port)  # nosec
