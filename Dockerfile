# ⚠️  THIS IS AN INTENTIONALLY VULNERABLE CONFIGURATION - FOR TESTING ONLY!
# This Dockerfile contains common security misconfigurations that ContainerGuard detects.

# DF002 - 'latest' tag (no way to know which version you're running)
FROM python:latest

# DF003 - Hardcoded API key directly in the image!
ENV API_KEY=super_secret_123
ENV DB_PASSWORD=admin1234

# DF004 - ADD instead of COPY
ADD . /app

WORKDIR /app

# DF006 - apt-get without --no-install-recommends
RUN apt-get update && apt-get install -y curl vim nano

# DF007 - Privileged port
EXPOSE 80

# Install dependencies
RUN pip install flask requests

# DF001 - No USER instruction = runs as root!
# DF005 - No HEALTHCHECK instruction!

CMD ["python", "app.py"]