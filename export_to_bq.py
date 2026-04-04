"""
BankPoint - Firestore to BigQuery Export
=========================================
Zero Cost Strategy:
- Uses BQ insert_rows_json (Free tier)
- Runs via GitHub Actions (FREE)
- Triggered hourly via cron
"""

import json
from datetime import datetime, timezone
from google.cloud import firestore, bigquery

PROJECT_ID = "onyx-stack-474405-h5"
DATASET    = "bankpoint_raw"

db = firestore.Client(project=PROJECT_ID)
bq = bigquery.Client(project=PROJECT_ID)

def now():
    return datetime.now(timezone.utc).isoformat()

def to_ts(val):
    if val is None:
        return None
    if hasattr(val, "isoformat"):
        return val.isoformat()
    return str(val)

def load_to_bq(table_id, rows):
    if not rows:
        print(f"  ⚠️  No rows to export for {table_id}")
        return
    table_ref = f"{PROJECT_ID}.{DATASET}.{table_id}"
    errors = bq.insert_rows_json(table_ref, rows)
    if errors:
        print(f"  ❌ Errors in {table_id}: {errors}")
    else:
        print(f"  ✅ Exported {len(rows)} rows → {table_id}")

def export_users():
    print("\n👤 Exporting users...")
    rows = []
    for doc in db.collection("users").stream():
        d = doc.to_dict()
        rows.append({
            "uid":         doc.id,
            "name":        d.get("name"),
            "email":       d.get("email"),
            "phone":       d.get("phone"),
            "created_at":  to_ts(d.get("created_at")),
            "exported_at": now(),
        })
    load_to_bq("users", rows)

def export_accounts():
    print("\n🏦 Exporting accounts...")
    rows = []
    for doc in db.collection("accounts").stream():
        d = doc.to_dict()
        rows.append({
            "account_id":   doc.id,
            "user_id":      d.get("user_id", ""),
            "account_type": d.get("account_type"),
            "balance":      float(d.get("balance", 0)),
            "created_at":   to_ts(d.get("created_at")),
            "exported_at":  now(),
        })
    load_to_bq("accounts", rows)

def export_transactions():
    print("\n💸 Exporting transactions...")
    rows = []
    for doc in db.collection("transactions").stream():
        d = doc.to_dict()
        rows.append({
            "transaction_id": doc.id,
            "from_account":   d.get("from_account", ""),
            "to_account":     d.get("to_account", ""),
            "amount":         float(d.get("amount", 0)),
            "description":    d.get("description", ""),
            "status":         d.get("status", "success"),
            "created_at":     to_ts(d.get("created_at")),
            "exported_at":    now(),
        })
    load_to_bq("transactions", rows)

def export_login_events():
    print("\n🔐 Exporting login events...")
    rows = []
    for doc in db.collection("login_events").stream():
        d = doc.to_dict()
        rows.append({
            "event_id":   doc.id,
            "user_id":    d.get("user_id", ""),
            "email":      d.get("email"),
            "login_at":   to_ts(d.get("login_at")),
            "ip_address": d.get("ip_address"),
            "status":     d.get("status", "success"),
        })
    load_to_bq("login_events", rows)

def run_export(request=None, context=None):
    print(f"\n🚀 BankPoint Export Started: {now()}")
    export_users()
    export_accounts()
    export_transactions()
    export_login_events()
    print(f"\n✅ Export Complete: {now()}")
    return "OK", 200

if __name__ == "__main__":
    run_export()
