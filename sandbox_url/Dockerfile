FROM python:3.11-slim

RUN apt-get update -y && apt-get install -y \
    wget \
    curl \
    dnsutils \
    net-tools \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

RUN pip install playwright requests && \
    playwright install chromium && \
    playwright install-deps chromium

WORKDIR /sandbox

COPY url_analysis.py /sandbox/url_analysis.py

ENTRYPOINT ["python3", "/sandbox/url_analysis.py"]