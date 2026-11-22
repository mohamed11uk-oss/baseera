FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Run as an unprivileged user (Chrome deep scan otherwise needs --no-sandbox as root). .dockerignore keeps .env out.
RUN useradd --create-home --uid 10001 baseera && mkdir -p /app/data/runtime && chown -R baseera /app/data/runtime
USER baseera
ENV BASEERA_MODE=live
EXPOSE 8000
CMD ["python", "-m", "baseera", "serve", "--host", "0.0.0.0", "--port", "8000"]
