import http.server
import socketserver

ADDRESS = "0.0.0.0"
PORT = 80

def handle_request(request, client_address, server):
    http.server.SimpleHTTPRequestHandler(
        request, client_address, server)

with socketserver.TCPServer((ADDRESS, PORT), handle_request) as httpd:
    print(f"Server running on {ADDRESS}:{PORT}")
    httpd.serve_forever()

