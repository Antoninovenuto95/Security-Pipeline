# Usa una base Python leggera
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

# Directory di lavoro dentro al container
WORKDIR /app

# Copia e installa le dipendenze Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia il codice dell'applicazione
COPY secure_pipeline ./secure_pipeline

# Entry point: esegue il modulo come CLI
ENTRYPOINT ["python", "-m", "secure_pipeline"]
