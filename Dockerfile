# Use official lightweight Python image
FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Install the system whois utility
RUN apt-get update && apt-get install -y whois && rm -rf /var/lib/apt/lists/*

# Copy the local code to the container
COPY . ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Run the web service using Gunicorn
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app