FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml .
COPY datasette_sierra_ils_auth/ datasette_sierra_ils_auth/
COPY README.md .

# Install plugin and datasette 1.0a23
RUN uv pip install --system "datasette==1.0a23" .

EXPOSE 8001

CMD ["datasette", "--host", "0.0.0.0", "--port", "8001"]
