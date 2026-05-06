FROM python:3.11-slim

WORKDIR /app
RUN pip install --no-cache-dir aiohttp

COPY server.py .

EXPOSE 8080
CMD ["python", "server.py"]
