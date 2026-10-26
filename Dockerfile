FROM python:3.13-slim

WORKDIR /app

RUN groupadd --system app \
    && useradd --system --gid app --home-dir /nonexistent --no-create-home app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app scanner.py README.md LICENSE ./

USER app
ENTRYPOINT ["python3", "/app/scanner.py"]
