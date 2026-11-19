"""Run the H3C to FortiGate mapping interface on the local computer."""

import argparse
from base64 import b64decode
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path

from translate import convert_config, decode_config, require, validate_mapping


MAX_CONFIG_BYTES = 16 * 1024 * 1024
MAX_BODY_BYTES = (MAX_CONFIG_BYTES + 2) // 3 * 4 + 512 * 1024
WEB = Path(__file__).resolve().parent / "web"
ASSETS = {
    "/": ("index.html", "text/html"),
    "/app.js": ("app.js", "text/javascript"),
    "/style.css": ("style.css", "text/css"),
}


def interface_inventory(report):
    routes = Counter(route["interface"] for route in report["routes"] if route.get("interface"))
    interfaces = [
        {"name": name, "ipv4": details["ipv4"], "dhcp": details["dhcp"],
         "layer2": details["layer2"], "aggregation_member": details["aggregation_member"],
         "route_count": routes[name]}
        for name, details in report["interfaces"].items()
    ]
    return {
        "interfaces": sorted(interfaces, key=lambda item: not item["route_count"]),
        "zones": [name for name in report["zones"] if name.casefold() != "local"],
        "version": report["source_version"],
        "inventory": report["inventory"],
    }


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(20)
        super().setup()

    def log_message(self, format, *args):
        pass

    def local_request(self):
        authority = f"127.0.0.1:{self.server.server_port}"
        return (self.headers.get("Host") == authority
                and self.headers.get("Origin") in (None, f"http://{authority}"))

    def respond(self, status, data, media_type):
        self.send_response(status)
        self.send_header("Content-Type", f"{media_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def json_response(self, status, data):
        self.respond(status, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json")

    def do_GET(self):
        if not self.local_request():
            self.json_response(403, {"error": "请使用启动时显示的本地地址访问。"})
        elif self.path in ASSETS:
            name, media_type = ASSETS[self.path]
            self.respond(200, (WEB / name).read_bytes(), media_type)
        else:
            self.json_response(404, {"error": "页面不存在。"})

    def do_POST(self):
        if not self.local_request():
            self.json_response(403, {"error": "请从本地界面发起转换。"})
            return
        if self.path not in {"/api/inspect", "/api/convert"}:
            self.json_response(404, {"error": "接口不存在。"})
            return
        if self.headers.get_content_type() != "application/json":
            self.json_response(415, {"error": "请求格式不支持。"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            require(0 < length <= MAX_BODY_BYTES, "请求超过支持的大小，或缺少配置文件。")
            raw = self.rfile.read(length)
            require(len(raw) == length, "配置文件未完整传输。")
            request = json.loads(raw)
            require(isinstance(request, dict) and isinstance(request.get("config"), str),
                    "请选择 H3C 配置文件。")
            data = b64decode(request["config"], validate=True)
            require(0 < len(data) <= MAX_CONFIG_BYTES, "配置文件必须非空且不超过 16 MiB。")
            mapping = request.get("mapping", {}) if self.path == "/api/convert" else {}
            cli, report = convert_config(*decode_config(data), *validate_mapping(mapping))
        except (ValueError, RecursionError, TimeoutError) as error:
            self.json_response(400, {"error": str(error)})
            return
        if self.path == "/api/inspect":
            self.json_response(200, interface_inventory(report))
        else:
            self.json_response(200, {"cli": cli, "report": report})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765, help="local port, default 8765")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    try:
        with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server:
            print(f"在浏览器打开 http://127.0.0.1:{server.server_port}/", flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        return
    except OSError as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
