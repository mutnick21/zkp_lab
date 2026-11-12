FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
RUN useradd --system --uid 10001 --home /app zkp \
 && mkdir -p /app/data && chown zkp /app/data

COPY server.py ./
COPY static ./static

USER zkp
EXPOSE 8080
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/scoreboard', timeout=2)" || exit 1

CMD ["python", "server.py", "--host", "0.0.0.0", "--port", "8080", "--state", "/app/data/state.json"]
