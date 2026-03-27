# Use a lightweight Python 3.12 image
FROM python:3.12-slim

# Install system dependencies (git is required for the GitHub cloning feature)
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Install security tools globally
RUN pip install --no-cache-dir semgrep pip-audit

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose the port FastAPI runs on
EXPOSE 8000

# Start the application
CMD ["uvicorn", "backend.api.main:app", "--host", "0.0.0.0", "--port", "8000"]