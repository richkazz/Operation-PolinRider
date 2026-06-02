FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends -y git \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN pip install --no-cache-dir ".[yara]"

ENTRYPOINT ["polinrider-guard"]
