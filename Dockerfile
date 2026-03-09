FROM kalilinux/kali-rolling

# Install Python and security tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    nikto \
    whatweb \
    whois \
    sslscan \
    dirb \
    dnsrecon \
    curl \
    metasploit-framework \
    && apt-get clean

# Set work directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip3 install -r requirements.txt --break-system-packages

# Copy project files
COPY . .

# Expose port
EXPOSE 5000

# Run app
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:5000", "--timeout", "300", "--workers", "2"]
```

---

## Step 2 — Update requirements.txt
```
flask
gunicorn