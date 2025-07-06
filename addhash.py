import sqlite3
import hashlib
import sys

# ————— CONFIGURATION —————
DB_PATH      = R"DB Directory"
TABLES       = ["table names"]
# Columns you do NOT want to hash
EXCLUDE_COLS = ["columns to exclude"]
# ——————————————————————

def sha256_hex(s: str) -> str:
    if s.isupper():
        s.lower().capitalize()
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def main(db_path: str, TABLE: str):
    print(f"Adding hashes to table {TABLE}")
    conn = sqlite3.connect(db_path)
    cur  = conn.cursor()

    cur.execute(f'PRAGMA table_info("{TABLE}");')
    cols_info = cur.fetchall()
    all_cols  = [row[1] for row in cols_info]

    # 2) Determine which to hash
    to_hash = [c for c in all_cols if c not in EXCLUDE_COLS]
    if not to_hash:
        print("No columns to hash!  Check EXCLUDE_COLS.")
        return

    for col in to_hash:
        hash_col = f"{col}_sha256"
        if hash_col not in all_cols:
            print(f"Adding column '{hash_col}'…")
            cur.execute(f'ALTER TABLE "{TABLE}" ADD COLUMN "{hash_col}" BLOB;')
        else:
            print(f"Column '{hash_col}' already exists, skipping.")
    conn.commit()

    for col in to_hash:
        hash_col = f"{col}_sha256"
        print(f"Hashing '{col}' → '{hash_col}'")
        cur.execute(f'SELECT rowid, "{col}" FROM "{TABLE}";')
        for rowid, value in cur.fetchall():
            raw = "" if value is None else str(value)
            h   = sha256_hex(raw)
            cur.execute(
                f'UPDATE "{TABLE}" SET "{hash_col}" = ? WHERE rowid = ?;',
                (h, rowid)
            )
        conn.commit()

    conn.close()
    print("All hashes computed.")

if __name__ == "__main__":
    for TABLE in TABLES:
        main(DB_PATH, TABLE)
