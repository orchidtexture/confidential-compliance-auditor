# Force amd64 architecture for Intel TDX compatibility
FROM --platform=linux/amd64 python:3.13-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy our source code into the container
COPY src/ ./src/

# Start the FastAPI server
CMD ["uvicorn", "src.cca_poc.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "trace", "--proxy-headers", "--forwarded-allow-ips", "*"]