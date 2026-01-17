# 1. Image de base légère
FROM python:3.10-slim

# 2. Optimisations Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 3. Dossier de travail
WORKDIR /app

# 4. Installation des dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copie du code (api) et des modèles
COPY api ./api
COPY models ./models

# 6. Port
EXPOSE 8001

# 7. Lancement
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8001"]