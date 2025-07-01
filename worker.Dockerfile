# Use the official Python image as a base
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# MODIFIED: Install build-essential which contains the C++ compiler
RUN apt-get update && apt-get install -y build-essential

# Copy only the dependency file first to leverage Docker cache
COPY ./poetry.lock ./pyproject.toml /app/

# Install poetry and then the project dependencies
RUN pip install poetry && poetry config virtualenvs.create false && poetry install --no-root --without dev

# --- ADDED: Pre-download the embedding model ---
# This RUN command will download the model and cache it inside the Docker image layer
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

# Copy the rest of the application code
COPY ./src/ /app/src/
COPY ./alembic/ /app/alembic/
COPY ./alembic.ini /app/

# Set the command to run the worker consumer
CMD ["poetry", "run", "python", "-m", "app.workers.consumer"]