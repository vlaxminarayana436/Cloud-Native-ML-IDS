FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DB_PATH=/data/security_events.db MODEL_DIR=/app/models
WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home app && mkdir -p /data /app/models && chown -R app:app /data /app
COPY --chown=app:app backend/app ./app
COPY --chown=app:app backend/ml ./ml
COPY --chown=app:app backend/models/model.joblib backend/models/model_metrics.json ./models/
USER app
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
