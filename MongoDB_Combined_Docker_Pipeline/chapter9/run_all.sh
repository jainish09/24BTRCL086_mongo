#!/usr/bin/env bash
# Runs every Chapter 9 lab, bakes the results into the image and pushes it to Docker Hub.
#
#   ./run_all.sh <your-dockerhub-username>
#
# Run "docker login" once before this.
set -euo pipefail

USER_NAME="${1:?usage: ./run_all.sh <your-dockerhub-username>}"
export LAB_IMAGE="${USER_NAME}/mongodb-lab09:1.0"
cd "$(dirname "$0")"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

step "Removing the Chapter 8 containers (same names mongo1/2/3); their data volumes are kept"
docker rm -f mongo1 mongo2 mongo3 mongo-arbiter >/dev/null 2>&1 || true

step "Building the lab image ${LAB_IMAGE}"
mkdir -p output
docker compose build --build-arg LAB_IMAGE="${LAB_IMAGE}" lab

step "Starting the 3-node replica set"
docker compose up -d mongo1 mongo2 mongo3

step "Setup";                               docker compose run --rm lab setup
step "Lab 9.1";                             docker compose run --rm lab 9.1
step "Activity 9.1 (Try it yourself)";      docker compose run --rm lab 9.1-try
step "Lab 9.2";                             docker compose run --rm lab 9.2

step "Rebuilding the image so it contains these results"
docker compose build --build-arg LAB_IMAGE="${LAB_IMAGE}" lab
docker tag "${LAB_IMAGE}" "${USER_NAME}/mongodb-lab09:latest"

step "Pushing to Docker Hub"
docker push "${LAB_IMAGE}"
docker push "${USER_NAME}/mongodb-lab09:latest"

step "Done"
echo "Docker Hub page: https://hub.docker.com/r/${USER_NAME}/mongodb-lab09"
echo "Results:         ./output/"
