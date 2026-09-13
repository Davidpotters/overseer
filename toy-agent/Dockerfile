FROM python:3.12-slim

RUN groupadd --gid 10001 agent && \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin agent

WORKDIR /app
COPY agent.py .

USER 10001:10001
ENTRYPOINT ["python3", "-u", "agent.py"]
