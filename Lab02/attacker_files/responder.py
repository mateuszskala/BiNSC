from http.server import BaseHTTPRequestHandler, HTTPServer

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()

        html = "<html>\n<body>\n<h1>Witaj! Ta domena została przejęta.</h1>\n</body>\n</html>\n"
        self.wfile.write(html.encode("utf-8"))


server = HTTPServer(("0.0.0.0", 80), SimpleHandler)
server.serve_forever()