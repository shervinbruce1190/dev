# Use official Python 3.10 image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src

# Set environment variable to avoid Python buffering output
ENV PYTHONUNBUFFERED=1

# Default command: run tests with coverage
CMD ["bash", "-c", "PYTHONPATH=src coverage run -m unittest discover -s src -p 'test_*.py' && coverage report"]
