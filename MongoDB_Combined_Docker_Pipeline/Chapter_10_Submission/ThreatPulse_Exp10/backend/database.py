import logging
from typing import Optional
from pymongo import MongoClient, ASCENDING, IndexModel
from pymongo.read_concern import ReadConcern
from pymongo.write_concern import WriteConcern
from pymongo.read_preferences import ReadPreference
from config import MONGODB_URI, DB_NAME

logger = logging.getLogger("threatpulse.db")
logging.basicConfig(level=logging.INFO)

_client: Optional[MongoClient] = None
_db = None


def get_client() -> MongoClient:
    global _client
    if _client is None:
        # 1. First check if explicit env URI works as a full replica set
        uris_to_try = [
            MONGODB_URI,
            "mongodb://mongo1:27017,mongo2:27017,mongo3:27017/?replicaSet=rs0",
            "mongodb://127.0.0.1:27020,127.0.0.1:27018,127.0.0.1:27019/?replicaSet=rs0",
        ]
        
        connected = False
        last_err = None
        for uri in uris_to_try:
            try:
                c = MongoClient(
                    uri,
                    serverSelectionTimeoutMS=2000,
                    connectTimeoutMS=2000,
                    retryWrites=True,
                    w="majority"
                )
                res = c.admin.command("hello")
                if res.get("isWritablePrimary", False) or res.get("ismaster", False):
                    _client = c
                    connected = True
                    logger.info(f"Connected to Replica Set URI: {uri}")
                    break
            except Exception as e:
                last_err = e
                continue

        # 2. If running on host where replica set hostnames are inside docker, probe ports for writable primary
        if not connected:
            ports = [27018, 27020, 27019, 27017]
            for port in ports:
                direct_uri = f"mongodb://127.0.0.1:{port}/?directConnection=true"
                try:
                    c = MongoClient(
                        direct_uri,
                        serverSelectionTimeoutMS=1500,
                        connectTimeoutMS=1500,
                        retryWrites=True,
                        w="majority"
                    )
                    res = c.admin.command("hello")
                    if res.get("isWritablePrimary", False):
                        _client = c
                        connected = True
                        logger.info(f"Connected to Writable Primary directly on port {port}: {direct_uri}")
                        break
                except Exception as e:
                    last_err = e
                    continue

        if not connected:
            raise RuntimeError(f"Could not connect to MongoDB replica set rs0. Last error: {last_err}")

    return _client


def get_database():
    global _db
    if _db is None:
        client = get_client()
        _db = client[DB_NAME]
        init_indexes(_db)
    return _db


def init_indexes(db):
    """
    Ensures required constraints, uniqueness, and TTL indices exist.
    """
    try:
        # 1. users: unique email
        db.users.create_index([("email", ASCENDING)], unique=True)
        # 2. sessions: TTL index on expires_at
        db.sessions.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
        db.sessions.create_index([("token", ASCENDING)], unique=True)
        # 3. wallets: unique user_id
        db.wallets.create_index([("user_id", ASCENDING)], unique=True)
        # 4. wallet_tx: index on tx_id and user_id
        db.wallet_tx.create_index([("tx_id", ASCENDING)], unique=True)
        db.wallet_tx.create_index([("user_id", ASCENDING)])
        # 5. subscriptions: unique user_id
        db.subscriptions.create_index([("user_id", ASCENDING)], unique=True)
        # 6. credit_ledger: index on user_id, txn_id
        db.credit_ledger.create_index([("user_id", ASCENDING)])
        db.credit_ledger.create_index([("txn_id", ASCENDING)])
        # 7. payments: unique payment_id
        db.payments.create_index([("payment_id", ASCENDING)], unique=True)
        # 8. credit_transfers: unique transfer_id
        db.credit_transfers.create_index([("transfer_id", ASCENDING)], unique=True)
        # 9. usage_log: index on user_id
        db.usage_log.create_index([("user_id", ASCENDING)])
        # 10. stock_inventory: unique item_key
        db.stock_inventory.create_index([("item_key", ASCENDING)], unique=True)
        # 11. coupons: unique code
        db.coupons.create_index([("code", ASCENDING)], unique=True)
        # 12. txn_receipts: unique receipt_id
        db.txn_receipts.create_index([("receipt_id", ASCENDING)], unique=True)
        db.txn_receipts.create_index([("user_id", ASCENDING)])
        logger.info("MongoDB Exp10 schema indexes & TTL initialized.")
    except Exception as e:
        logger.warning(f"Index initialization warning: {e}")


# Explicit collection getters
def col_users(): return get_database()["users"]
def col_sessions(): return get_database()["sessions"]
def col_wallets(): return get_database()["wallets"]
def col_wallet_tx(): return get_database()["wallet_tx"]
def col_subscriptions(): return get_database()["subscriptions"]
def col_credit_ledger(): return get_database()["credit_ledger"]
def col_payments(): return get_database()["payments"]
def col_credit_transfers(): return get_database()["credit_transfers"]
def col_usage_log(): return get_database()["usage_log"]
def col_stock(): return get_database()["stock_inventory"]
def col_coupons(): return get_database()["coupons"]
def col_receipts(): return get_database()["txn_receipts"]
def col_reports(): return get_database()["threat_reports"]
