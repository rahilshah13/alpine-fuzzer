FROM alpine:latest

RUN apk update && apk add --no-cache \
    build-base \
    git \
    libedit-dev \
    openssl-dev \
    libffi-dev \
    python3

WORKDIR /app

RUN git clone https://github.com/trealla-prolog/trealla.git /tmp/trealla && \
    cd /tmp/trealla && \
    make NOTHREADS=1 && \
    cp tpl /usr/local/bin/tpl && \
    rm -rf /tmp/trealla

COPY main.c index.jsx ml.js fuzzer.pl ./
RUN gcc -O2 -fno-stack-protector -D_GNU_SOURCE main.c -o /usr/local/bin/fuzz_runner -ldl

RUN mkdir -p /app/dist && cp index.jsx ml.js /app/dist/ && cat << 'EOF' > /app/dist/index.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Exhaustive Concurrent Fuzzing & Diffusion VAE</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50">
    <div id="app"></div>
    <script type="module" src="/index.jsx"></script>
</body>
</html>
EOF

RUN cat << 'EOF' > /app/server.py
import os
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import HTTPServer, SimpleHTTPRequestHandler

class FuzzHandler(SimpleHTTPRequestHandler):
    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        '.jsx': 'application/javascript',
        '.js': 'application/javascript',
    }

    def translate_path(self, path):
        if path == '/' or path == '':
            return '/app/dist/index.html'
        return os.path.join('/app/dist', path.lstrip('/'))

    def do_GET(self):
        if self.path == '/api/stream':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
            
            find_proc = subprocess.run(
                ['find', '/lib', '/usr/lib', '/bin', '/sbin', '/usr/bin', '/usr/sbin', '-name', '*.so*', '-o', '-name', '*.exe', '-type', 'f'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            binaries = [line.strip() for line in find_proc.stdout.splitlines() if line.strip()]

            def run_fuzz(target):
                try:
                    res = subprocess.run(['/usr/local/bin/fuzz_runner', target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
                    status = "UnknownError"
                    duration_us = 0
                    for line in res.stdout.splitlines():
                        if line.startswith("FailMode: "):
                            status = line[len("FailMode: "):].strip()
                        elif line.startswith("ExecutionTimeUs: "):
                            try:
                                duration_us = int(line[len("ExecutionTimeUs: "):].strip())
                            except ValueError:
                                pass
                    
                    if status == "None":
                        stat_text = "WORKED"
                        details = "dlopen/dlclose completed cleanly."
                    elif status == "SystemCoreLibrary":
                        stat_text = "SKIPPED"
                        details = "Bypassed core musl runtime."
                    elif status == "LibraryNotFound":
                        stat_text = "FAILED (Target Missing)"
                        details = "Shared object binary missing."
                    else:
                        stat_text = f"FAILED ({status})"
                        details = f"Execution failed under failmode {status}."

                    return {
                        "target": target,
                        "domain": target,
                        "status": stat_text,
                        "duration_us": duration_us,
                        "details": details
                    }
                except subprocess.TimeoutExpired:
                    return {
                        "target": target,
                        "domain": target,
                        "status": "TIMEOUT",
                        "duration_us": 10000000,
                        "details": "Exceeded 10-second execution timeout."
                    }
                except Exception as e:
                    return {
                        "target": target,
                        "domain": target,
                        "status": "ERROR",
                        "duration_us": 0,
                        "details": str(e)
                    }

            with ThreadPoolExecutor(max_workers=12) as executor:
                futures = {executor.submit(run_fuzz, bin_path): bin_path for bin_path in binaries}
                for future in as_completed(futures):
                    item = future.result()
                    payload = json.dumps({"type": "progress", "item": item})
                    self.wfile.write(f"data: {payload}\n\n".encode('utf-8'))
                    self.wfile.flush()

            complete_payload = json.dumps({"type": "complete"})
            self.wfile.write(f"data: {complete_payload}\n\n".encode('utf-8'))
            self.wfile.flush()
        else:
            super().do_GET()

def run_server():
    server = HTTPServer(('0.0.0.0', 8080), FuzzHandler)
    server.serve_forever()

if __name__ == '__main__':
    run_server()
EOF

EXPOSE 8080
CMD ["python3", "server.py"]