# Use uma imagem Python leve como base
FROM python:3.11-slim

# Evita que o Python gere arquivos .pyc e permite logs em tempo real
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Instala dependências do sistema necessárias para compilar algumas libs se houver
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copia apenas o requirements primeiro para aproveitar o cache de camadas do Docker
COPY requirements.txt .

# Instala as dependências do Python
RUN pip install --no-cache-dir -r requirements.txt

# Copia o restante do código do projeto
COPY . .

# Cria o diretório de dados para o SQLite se não existir e dá permissão
RUN mkdir -p data

# Expõe a porta que o FastAPI usa
EXPOSE 8000

# Comando para rodar a aplicação usando uvicorn
# Usamos 0.0.0.0 para que o container aceite conexões externas de fora dele (do seu Windows)
CMD ["python", "app.py"]
