"""
pyproxy.monitoring.routes.py

Defines and registers monitoring-related routes for the Flask application,
including endpoints for system information, configuration, and a secured
HTML-based index page.
"""

from flask import jsonify, render_template


def register_routes(app, auth, proxy_server, ProxyMonitor):
    """
    Registers the monitoring routes to the Flask app, secured with HTTP Basic Auth.

    Args:
        app (Flask): The Flask application instance.
        auth (HTTPBasicAuth): The HTTP Basic Auth instance used to secure routes.
        proxy_server (ProxyServer): The running ProxyServer instance to monitor.
        ProxyMonitor (class): The monitoring class used to gather runtime information.
    """

    @app.route("/")
    @auth.login_required
    def index():
        """
        Serves the main index HTML page for the monitoring dashboard.

        Returns:
            Response: Rendered HTML page.
        """
        return render_template("index.html")

    @app.route("/monitoring", methods=["GET"])
    @auth.login_required
    def monitoring():
        """
        Provides real-time monitoring information about the ProxyServer,
        including process, thread, and connection status.

        Returns:
            Response: JSON object containing monitoring data.
        """
        monitor = ProxyMonitor(proxy_server)
        return jsonify(monitor.get_process_info())

    @app.route("/config", methods=["GET"])
    @auth.login_required
    def config():
        """
        Returns the current configuration of the ProxyServer, including
        host, port, debug mode, and optional components like logger, filter,
        and SSL configuration.

        Returns:
            Response: JSON object containing configuration data.
        """
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
            "flask_port": proxy_server.monitoring_config.flask_port,
        }
        return jsonify(config_data)
