FROM python:3.12-slim

# Create a non-root user to run the app
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /workspace

# Install system dependencies for PostgreSQL driver and curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Change ownership of the workspace to the non-root user
RUN chown -R appuser:appuser /workspace

# Switch to the non-root user
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
