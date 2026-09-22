FROM python:3.12-slim

WORKDIR /app

# Dépendances système : psycopg2, weasyprint, + Nmap (outil de scan) et Go (pour Nuclei)
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    nmap \
    golang-go \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Installe Nuclei (scanner de vulnérabilités basé sur des templates)
ENV GOPATH=/root/go
ENV PATH=/root/go/bin:$PATH
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && nuclei -update-templates || true
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6 \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.8
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
