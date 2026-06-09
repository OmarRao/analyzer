FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 5000

# Runs as root - intentional misconfiguration for demo
CMD ["python", "app.py"]
