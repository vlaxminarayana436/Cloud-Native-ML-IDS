FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /agent
# iptables is only used if an enforcer is explicitly enabled and has NET_ADMIN.
RUN apt-get update && apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/*
COPY agent/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY agent/agent.py agent/policy_enforcer.py agent/enforce.py ./
CMD ["python", "agent.py"]
