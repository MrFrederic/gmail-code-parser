FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py .

EXPOSE 8080

RUN mkdir -p /data
VOLUME /data

CMD ["python", "main.py"]
