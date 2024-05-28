FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY force_evaluate.py .

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "force_evaluate.py"]
