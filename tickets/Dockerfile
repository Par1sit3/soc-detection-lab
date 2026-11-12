# Ticket queue: Python standard library only, runs as an unprivileged user.
FROM python:3.12-alpine
RUN adduser -D -u 10001 tickets && mkdir /data && chown tickets /data
COPY app.py /app/app.py
USER tickets
VOLUME /data
EXPOSE 8080
CMD ["python3", "/app/app.py"]
