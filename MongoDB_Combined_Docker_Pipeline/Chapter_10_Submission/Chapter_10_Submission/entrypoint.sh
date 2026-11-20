#!/bin/bash
# Entry point of the Chapter 10 lab image.
#
# The image has two roles:
#   server   one bank server: a mongod member of replica set "rs0"
#   app      the payment app: initiates the replica set if needed, then runs a lab
set -euo pipefail

RS_URI="mongodb://bank-primary:27017,bank-backup:27017,bank-dr:27017/?replicaSet=rs0"
SERVERS=(bank-primary bank-backup bank-dr)

usage() {
  cat <<'EOF'
Chapter 10 labs - Transactions: payments, retries, failover, inventory

Set up (once):
  docker run --rm justkamlesh21/mongodb-lab10 compose > docker-compose.yml
  docker compose up -d                       # bank-primary, bank-backup, bank-dr

Run:
  docker compose run --rm app demo           # everything below, in order
  docker compose run --rm app lab10.1        # Lab 10.1: 14 payment scenarios
  docker compose run --rm app try10.1        # Activity 10.1: retry + backoff, then failover
  docker compose run --rm app failover       # bank-primary crashes, bank-backup takes over
  docker compose run --rm app lab10.2        # Lab 10.2: inventory reservation + checkout
  docker compose run --rm app status         # replica set members and their state

Manual failover demo (two terminals):
  docker compose run --rm app paystream      # terminal 1: a payment every 0.5 s
  docker kill bank-primary                   # terminal 2: the main bank server crashes
  docker start bank-primary                  #             and comes back

Without the servers:
  docker run --rm justkamlesh21/mongodb-lab10 results   # output recorded when the labs were completed
  docker run --rm justkamlesh21/mongodb-lab10 compose   # print docker-compose.yml

Clean up:
  docker compose down -v
EOF
}

server() {
  # The base image's entrypoint prepares /data/db and drops to the mongodb user.
  exec docker-entrypoint.sh mongod --replSet rs0 --bind_ip_all --wiredTigerCacheSizeGB 0.25
}

wait_for_servers() {
  local server deadline=$((SECONDS + 60))
  for server in "${SERVERS[@]}"; do
    until mongosh --host "$server" --quiet --eval 'db.runCommand({ ping: 1 }).ok' > /dev/null 2>&1; do
      if [ $SECONDS -ge $deadline ]; then
        echo "ERROR: bank server $server is not reachable." >&2
        echo "Start the servers first:  docker compose up -d   (or: docker start $server)" >&2
        exit 1
      fi
      sleep 1
    done
  done
}

# First run only: create rs0 with the bank priorities. Then wait until the main
# bank server is primary and the other two are secondaries.
initiate() {
  mongosh --host bank-primary --quiet --eval '
    try { rs.status() } catch (error) {
      rs.initiate({ _id: "rs0", members: [
        { _id: 0, host: "bank-primary:27017", priority: 2 },
        { _id: 1, host: "bank-backup:27017",  priority: 1 },
        { _id: 2, host: "bank-dr:27017",      priority: 0 } ] })
    }' > /dev/null
  local ready='const s = rs.status().members;
    print(s.every(m => m.stateStr == (m.name.startsWith("bank-primary") ? "PRIMARY" : "SECONDARY")))'
  local deadline=$((SECONDS + 120))
  until [ "$(mongosh "$RS_URI" --quiet --eval "$ready" 2>/dev/null)" = "true" ]; do
    if [ $SECONDS -ge $deadline ]; then
      echo "ERROR: bank-primary did not become primary within 120 s." >&2
      exit 1
    fi
    sleep 1
  done
}

status() {
  mongosh "$RS_URI" --quiet --eval '
    const priority = Object.fromEntries(rs.conf().members.map(m => [m.host, m.priority]));
    rs.status().members.forEach(m => print("  " + m.name.padEnd(20) + m.stateStr.padEnd(11) +
      "priority=" + priority[m.name] + "  health=" + m.health))'
}

prepare() {
  echo "Connecting to the bank servers (replica set rs0) ..."
  wait_for_servers
  initiate
  status
  echo
}

# run_lab <folder> <script>: with RECORD=1 the screen output is also saved next
# to the script, which is how the recorded results were produced.
run_lab() {
  local script="/lab/$1/$2"
  if [ "${RECORD:-0}" = 1 ]; then
    python3 -u "$script" | tee "${script%.py}_output.txt"
  else
    python3 -u "$script"
  fi
  echo
}

lab_10_1()  { run_lab Activity_10.1 lab_10_1_bank_transfer.py; }
try_10_1()  { run_lab Activity_10.1_Try_It_Yourself try_10_1_retry_backoff.py; }
failover()  { run_lab Activity_10.1_Try_It_Yourself failover_experiment.py; }
lab_10_2()  { run_lab Activity_10.2 lab_10_2_inventory_reservation.py; }

show_results() {
  local file
  for file in /lab/Activity_*/*_output.txt; do
    echo "===== $file ====="
    cat "$file"
    echo
  done
}

case "${1:-help}" in
  help|-h|--help) usage ;;
  server)         server ;;
  compose)        cat /lab/docker-compose.yml ;;
  results)        show_results ;;
  status)         prepare ;;
  demo)           prepare; lab_10_1; try_10_1; failover; lab_10_2 ;;
  lab10.1)        prepare; lab_10_1 ;;
  try10.1)        prepare; try_10_1; failover ;;
  failover)       prepare; failover ;;
  lab10.2)        prepare; lab_10_2 ;;
  paystream)      prepare; exec python3 -u /lab/Activity_10.1_Try_It_Yourself/paystream.py ;;
  *)              exec "$@" ;;
esac
