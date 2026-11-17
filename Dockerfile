FROM python:3.12-slim

RUN pip install --no-cache-dir uv==0.8.13

WORKDIR /code

COPY ./pyproject.toml ./README.md ./uv.lock* ./
COPY ./msa ./msa
COPY ./quota ./quota
COPY ./billing ./billing
COPY ./bot ./bot

ENV UV_DEFAULT_INDEX=https://pypi.org/simple
ENV PYTHONUNBUFFERED=1
RUN uv lock && uv sync --locked

EXPOSE 8080

CMD ["uv", "run", "uvicorn", "bot.server:app", "--host", "0.0.0.0", "--port", "8080"]
