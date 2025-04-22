FROM python:3.13-slim as builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.13-slim
RUN useradd -m -s /bin/bash pyproxy
WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .
RUN chown -R pyproxy:pyproxy /app
USER pyproxy
EXPOSE 8080
ENTRYPOINT ["python3", "pyproxy.py"]
