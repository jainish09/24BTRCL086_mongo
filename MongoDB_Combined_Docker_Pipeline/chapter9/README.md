# MongoDB Chapter 9 Lab - Write Concerns and Network Partitions

Harshit Sethiya · 24BTRCL082 · AIML-B

| Command | Task |
|---|---|
| `docker compose run --rm lab 9.1` | Lab 9.1 - 1,000 inserts each with w: 1, w: majority, w: all; total time, average latency, table |
| `docker compose run --rm lab 9.1-try` | Activity 9.1 - the same with j: false and j: true |
| `docker compose run --rm lab 9.2` | Lab 9.2 - `docker network disconnect` one secondary, then both; w: 1 / w: majority inserts; step-down; reconnect and catch-up |
| `docker compose run --rm lab observer` | Lab 8.2 failover observer (Terminal 1 for a manual Lab 9.2 run) |
| `docker compose run --rm lab results` | Results of the author's own run, stored in the image |

## Demonstration from Docker Hub only

```bash
mkdir lab09 && cd lab09
docker run --rm <user>/mongodb-lab09:1.0 compose > docker-compose.yml
docker compose up -d mongo1 mongo2 mongo3
docker compose run --rm lab setup
docker compose run --rm lab 9.1
docker compose run --rm lab 9.1-try
docker compose run --rm lab 9.2
docker compose down
```

## Manual Lab 9.2 (three terminals, as in the lab sheet)

```bash
# Terminal 1
docker compose run --rm lab observer
# Terminal 2
docker ps
docker network disconnect mongo-net-09 mongo3
docker network connect mongo-net-09 mongo3
```

Output of every run is written to `./output` (terminal text + JSON of every MongoDB command and reply).
