# Combined MongoDB Docker Pipeline (Chapters 7, 8, 9)

This bundle combines:
- `lab7/`: Chapter 7 FastAPI + browser dashboard
- `chapter8/`: Chapter 8 replica-set and failover scripts
- `chapter9/`: Chapter 9 write-concern and network-partition experiments
- one root `docker-compose.yml` with a shared 3-node MongoDB replica set

## Before you start

1. Install and open Docker Desktop; wait until its engine is running.
2. Extract this ZIP to a normal Windows folder, e.g. `C:\Users\<you>\Downloads\MongoDB_Combined_Docker_Pipeline`.
3. Open that folder and double-click `run-pipeline.bat`.

The script builds the dashboard and lab images, starts MongoDB, initializes the replica set, then runs Chapter 8.1, Chapter 8.2, Chapter 9.1, Chapter 9.1-try, and Chapter 9.2 in order. It stops at the first error instead of silently continuing.

Dashboard: http://localhost:8080

## Important notes

- This is a local educational lab, not a production deployment.
- Chapter 9.2 intentionally disconnects and reconnects MongoDB containers from their Docker network. The lab runner mounts the Docker socket for that reason. Do not run it against production containers.
- The Chapter 7 dashboard uses the local combined replica set; the original live `.env` file was intentionally excluded to avoid shipping database credentials.
- Chapter 8 JSON files are written alongside their scripts. Chapter 9 output logs are saved in `chapter9\output\`.
- MongoDB data persists in named Docker volumes. `stop-pipeline.bat` stops containers but keeps those volumes.
- To fully reset the MongoDB lab data, first stop the stack, then run `docker compose down -v` from this folder. This permanently deletes the local MongoDB volumes.

## Run an individual Chapter 9 experiment

From CMD in this folder:
- `docker compose --profile tools run --rm lab9 setup`
- `docker compose --profile tools run --rm lab9 9.1`
- `docker compose --profile tools run --rm lab9 9.1-try`
- `docker compose --profile tools run --rm lab9 9.2`

## Architecture

The Chapter 7 dashboard and the Chapter 8/9 experiments share the same local MongoDB replica set (`mongo1`, `mongo2`, `mongo3`) on `combined-mongo-net`. Container names are prefixed with `combined-` so they do not collide with containers from the original standalone lab.
