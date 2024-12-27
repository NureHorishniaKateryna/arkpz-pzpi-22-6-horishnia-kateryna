FROM python:3.12-alpine
WORKDIR "/smartlights"

RUN apk add build-base libpq libpq-dev
COPY requirements.txt requirements.txt
RUN pip install gunicorn -r requirements.txt

COPY . .

ENTRYPOINT ["gunicorn", "app:app", "--workers", "1", "--bind", "0.0.0.0:8080", "--preload"]