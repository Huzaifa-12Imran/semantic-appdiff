FROM python:3.11-slim

LABEL maintainer="apidiff"
LABEL description="Semantic API diff tool — detects behavioral regressions, not just schema changes"

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .
RUN pip install --no-cache-dir --no-deps -e .

# Create output directory
RUN mkdir -p /apidiff-report

ENTRYPOINT ["apidiff"]
CMD ["--help"]
