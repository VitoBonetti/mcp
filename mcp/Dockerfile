# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory
WORKDIR /opt/vulnai/mcp

# Install system dependencies for WeasyPrint
RUN apt-get update && apt-get install -y \
    libpango-1.0-0 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    libpangoft2-1.0-0 \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
# We copy the 'mcp' directory into the workdir
COPY mcp/ .

# Expose the port the app runs on
EXPOSE 8080

# Define the command to run your app
CMD ["uvicorn", "mcp_server:app", "--host", "0.0.0.0", "--port", "8080"]