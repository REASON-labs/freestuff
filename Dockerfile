FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as an unprivileged user. A fixed UID (not just a name) is what makes the
# volume permissions reproducible across rebuilds and hosts.
#
# UPGRADING AN EXISTING DEPLOYMENT: a /data volume created by an older image is
# owned by root, and this container can no longer write to it. Fix it once,
# before starting the new image:
#
#   docker compose run --rm --user root freestuff chown -R 10001:10001 /data
#
# New deployments need nothing — the empty volume inherits the ownership set
# below when Docker first populates it from the image.
RUN groupadd --gid 10001 freestuff \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin freestuff \
 && mkdir -p /data/uploads \
 && chown -R 10001:10001 /data

VOLUME ["/data"]
USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"

# 2 workers is plenty for a friends-and-family board. Note that the in-memory
# rate limiter keeps per-worker counters, so raising this number loosens the
# effective limits proportionally — see RATE_LIMITS in app.py.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "60", "app:app"]
