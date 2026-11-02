FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    AISCA_HOME=/app

# Install runtime deps (including nmap) and minimal build deps for wheels
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       nmap \
       libcairo2 \
       libpango-1.0-0 \
       libpangocairo-1.0-0 \
       libpangoft2-1.0-0 \
       libgdk-pixbuf-2.0-0 \
       libffi-dev \
       libssl-dev \
       libxml2 \
       libxslt1.1 \
       libjpeg-dev \
       zlib1g-dev \
       build-essential \
       pkg-config \
       python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR ${AISCA_HOME}

# Copy only requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY . ${AISCA_HOME}

# Create a non-root user and adjust permissions
RUN adduser --disabled-password --gecos "" aisca \
    && mkdir -p /data \
    && chown -R aisca:aisca ${AISCA_HOME} /data

# Drop build deps to slim the image (attempt to remove compilers)
RUN apt-get remove -y --purge build-essential python3-dev pkg-config \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

USER aisca

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
