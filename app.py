from flask import Flask, request, render_template
import socket

app = Flask(__name__)

def scan_ports(host, start=1, end=1024):
    open_ports = []
    
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
    
    return open_ports


@app.route("/", methods=["GET", "POST"])
def index():
    ports = []
    host = ""

    if request.method == "POST":
        host = request.form["host"]
        host_ip = socket.gethostbyname(host)
        ports = scan_ports(host_ip)

    return render_template("index.html", ports=ports, host=host)


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)