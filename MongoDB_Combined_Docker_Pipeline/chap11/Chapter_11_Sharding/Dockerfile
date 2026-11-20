# Dockerfile for Chapter 11: MongoDB Sharding Lab Runner
# Matches Chapter 10 packaging style: official mongo:7.0 base with Python 3 + pymongo.
FROM mongo:7.0

LABEL maintainer="Senior MongoDB Engineer"
LABEL lab="Chapter 11 - MongoDB Sharding"

WORKDIR /lab

# Install Python 3 and pymongo driver
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip \
 && pip3 install --no-cache-dir pymongo==4.10.1 \
 && rm -rf /var/lib/apt/lists/*

# Copy lab files
COPY . /lab

ENV RUNNING_IN_CONTAINER=1
ENV PYTHONUNBUFFERED=1

CMD ["python3", "run_lab11.py", "--container"]
