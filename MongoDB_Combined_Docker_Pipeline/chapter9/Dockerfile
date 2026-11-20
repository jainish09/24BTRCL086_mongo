# Chapter 9 lab image: Python 3.10 + PyMongo + Docker SDK + all Lab 9 scripts
# and the results of the author's own run (in /lab/results).
FROM python:3.10-slim

ARG LAB_IMAGE=mongodb-lab09:local
ENV LAB_IMAGE=${LAB_IMAGE} \
    OUTPUT_DIR=/lab/output \
    PYTHONUNBUFFERED=1

WORKDIR /lab
RUN pip install --no-cache-dir pymongo==4.10.1 docker==7.1.0

COPY scripts/ /lab/
COPY docker-compose.yml README.md /lab/
COPY output/ /lab/results/

LABEL org.opencontainers.image.title="MongoDB Chapter 9 Lab - write concerns and network partitions" \
      org.opencontainers.image.authors="Harshit Sethiya (24BTRCL082)"

ENTRYPOINT ["python", "/lab/lab.py"]
CMD ["help"]
