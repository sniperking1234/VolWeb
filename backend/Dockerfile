# Stage 1: Install dependencies
FROM python:3.12.6 AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/app/.local/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --user-group --create-home --no-log-init --shell /bin/bash app
USER app

WORKDIR /home/app/web
ENV PATH="/home/app/.local/bin:$PATH"

COPY requirements.txt .

RUN pip install --upgrade pip \
    && pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Copy only the necessary parts from builder
FROM python:3.12.6

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/app/.local/bin:$PATH" \
    APP_HOME=/home/app/web

RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --user-group --create-home --no-log-init --shell /bin/bash app \
    && mkdir -p $APP_HOME/staticfiles \
    && mkdir -p $APP_HOME/media \
    && mkdir -p $APP_HOME/media/temp_uploads \
    && mkdir -p $APP_HOME/media/symbols \
    && chown -R app:app $APP_HOME

WORKDIR $APP_HOME
ENV PATH="/home/app/.local/bin:$PATH"

COPY --chown=app:app --from=builder /home/app/.local /home/app/.local
COPY --chown=app:app . $APP_HOME

RUN chmod +x ./entrypoint.sh

RUN echo '#!/bin/sh\n\
# Fix permissions for mounted volumes\n\
if [ -d "/home/app/web/media" ]; then\n\
    chown -R app:app /home/app/web/media || true\n\
    chmod -R 755 /home/app/web/media || true\n\
fi\n\
if [ -d "/home/app/web/staticfiles" ]; then\n\
    chown -R app:app /home/app/web/staticfiles || true\n\
    chmod -R 755 /home/app/web/staticfiles || true\n\
fi\n\
# Switch to app user and run the original entrypoint\n\
exec gosu app /home/app/web/entrypoint.sh "$@"' > /entrypoint-wrapper.sh && \
    chmod +x /entrypoint-wrapper.sh

RUN apt-get update && apt-get install -y gosu && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/entrypoint-wrapper.sh"]