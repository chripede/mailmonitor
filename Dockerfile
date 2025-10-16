# Build stage
FROM ghcr.io/astral-sh/uv:python3.13-trixie AS build

WORKDIR /app

# Kopier pyproject.toml og uv.lock og installer afhængigheder
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev

# Kopier kildekode
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev

# Runtime stage
FROM ghcr.io/astral-sh/uv:python3.13-trixie AS runtime

RUN curl -fsSL https://github.com/aptible/supercronic/releases/latest/download/supercronic-linux-amd64 -o /usr/local/bin/supercronic \
    && chmod +x /usr/local/bin/supercronic

WORKDIR /app
COPY --from=build /app .

# Kopier cronjob definition
COPY mailmon-cron /etc/cron.d/mailmon-cron
RUN chmod 0644 /etc/cron.d/mailmon-cron

# Start cron i foreground
CMD ["supercronic", "-debug", "/etc/cron.d/mailmon-cron"]

