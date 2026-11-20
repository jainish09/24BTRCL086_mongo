# Chapter 10 labs in one image. The same image runs as each bank server
# (a member of the replica set) and as the payment app that runs the labs.
#
#   docker build -t justkamlesh21/mongodb-lab10 .
#   docker run --rm justkamlesh21/mongodb-lab10 compose > docker-compose.yml
#   docker compose up -d && docker compose run --rm app demo

FROM mongo:7.0

ARG DOCKER_CLI_VERSION=27.3.1

# python + pymongo for the labs, matplotlib for the throughput chart, and the
# Docker CLI so the failover experiment can stop and start the bank servers.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip curl ca-certificates \
 && pip3 install --no-cache-dir pymongo==4.10.1 matplotlib==3.9.2 \
 && curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_CLI_VERSION}.tgz" \
    | tar -xz -C /usr/local/bin --strip-components=1 docker/docker \
 && apt-get purge -y curl && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /lab
COPY . /lab

# Strip Windows line endings (the files are edited on Windows).
RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh

ENTRYPOINT ["/lab/entrypoint.sh"]
CMD ["help"]
