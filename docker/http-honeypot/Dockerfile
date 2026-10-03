FROM python:3.11.16-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
# Pinned to the version in uv.lock. This image is attacker-facing, so it must
# not drift with whatever `pip install aiohttp` resolves to on build day.
RUN pip install --no-cache-dir aiohttp==3.14.3 \
 && groupadd --system --gid 10002 httpd \
 && useradd  --system --uid 10002 --gid httpd --no-create-home --shell /sbin/nologin httpd

COPY --chown=root:root server.py .

# Non-root: a compromise of this process must not start as root in the
# container. 8080 is unprivileged, so no capability is needed to bind it.
USER httpd

EXPOSE 8080
CMD ["python", "server.py"]
