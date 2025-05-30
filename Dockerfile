FROM python:3.13-slim as builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p logs
RUN chown -R 1000:1000 /app


FROM gcr.io/distroless/python3-debian12:nonroot
USER 1000:1000
WORKDIR /app
COPY --from=builder /usr/local /usr/local
COPY --from=builder /app /app
EXPOSE 8080
ENTRYPOINT ["python3", "-m", "pyproxy.pyproxy"]
