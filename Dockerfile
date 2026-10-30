FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nftables conntrack iproute2 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1
EXPOSE 8095
CMD ["python", "web.py"]
