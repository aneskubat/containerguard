# ⚠️  OVO JE NAMJERNO RANJIVA KONFIGURACIJA - SAMO ZA TESTIRANJE!
# Ovaj Dockerfile sadrži uobičajene sigurnosne propuste koje ContainerGuard detektuje.

# DF002 - 'latest' tag (nikad ne znaš koja je verzija)
FROM python:latest

# DF003 - Hardcoded API ključ direktno u image!
ENV API_KEY=super_secret_123
ENV DB_PASSWORD=admin1234

# DF004 - ADD umjesto COPY
ADD . /app

WORKDIR /app

# DF006 - apt-get bez --no-install-recommends
RUN apt-get update && apt-get install -y curl vim nano

# DF007 - Privilegovani port
EXPOSE 80

# Instaliraj dependencije
RUN pip install flask requests

# DF001 - Nema USER instrukcije = pokreće se kao root!
# DF005 - Nema HEALTHCHECK instrukcije!

CMD ["python", "app.py"]