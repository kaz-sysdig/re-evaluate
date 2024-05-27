# ベースイメージとしてPython 3.11を使用
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY script.py .

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "script.py"]
