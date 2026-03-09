import atexit
import binascii

from cryptography import x509
from pgmq import PGMQueue
from sqlalchemy import URL, create_engine, text
from sqlmodel import Session
from sortedcontainers import SortedSet

from .config import POSTGRES_PASSWORD, POSTGRES_USER, PG_HOST, PG_PORT

queue = PGMQueue(
    host=PG_HOST,
    port=PG_PORT,
    username=POSTGRES_USER,
    password=POSTGRES_PASSWORD,
    database="stepca"
)

url_object = URL.create(
    "postgresql",
    username=POSTGRES_USER,
    password=POSTGRES_PASSWORD,
    host=PG_HOST,
    port=PG_PORT,
    database="stepca")

engine_stepca = create_engine(url_object)


@atexit.register
def close_psycopg_pools():
    import gc
    import psycopg_pool
    [obj.close() for obj in gc.get_objects() if isinstance(obj, psycopg_pool.ConnectionPool)]


def process_rows(session: Session, table: str, batch_size: int, callback):
    offset = 0

    while True:
        rows = session.execute(
            text("SELECT * FROM " + table + " LIMIT :limit OFFSET :offset"),
            {"limit": batch_size, "offset": offset}
        ).fetchall()

        if not rows:
            break

        i = 0

        for row in rows:
            callback(row, table)
            i += 1

        print(f"[!] Processed {offset + i} rows in {table}...")
        offset += batch_size


def run():
    print("[!] Starting reindex...")

    x509_cert_order = SortedSet()

    def add_cert_order(row, _table):
        serial_no = bytes(row._mapping['nkey']).decode("ascii")
        cert = x509.load_der_x509_certificate(binascii.unhexlify(row._mapping['nvalue'].hex()))
        x509_cert_order.add((cert.not_valid_before_utc.isoformat(), serial_no))

    def queue_row(row, table):
        mapped_hex = {k: '\\x' + v.hex() for k, v in row._mapping.items()}
        queue.send("event_queue", {
            "table": table,
            "operation": "resync",
            "data": mapped_hex
        })

    TABLES = {"x509_certs", "x509_certs_data", "acme_certs", "acme_accounts", "revoked_x509_certs"}
    BATCH_SIZE = 100

    with Session(engine_stepca) as session:
        session.execute(text("LOCK TABLE " + (", ".join(TABLES)) + " IN SHARE MODE"))

        print("[!] Figuring out the chronological insertion order for x509_certs")
        process_rows(session, "x509_certs", BATCH_SIZE, callback=add_cert_order)

        print("[!] Processing x509_certs")
        i = 0
        for nbf, serial_no in x509_cert_order:
            row = session.execute(
                text("SELECT * FROM x509_certs WHERE nkey = :nkey"),
                {"nkey": serial_no}
            ).fetchone()
            queue_row(row, table="x509_certs")
            i += 1

            if i % BATCH_SIZE == 0:
                print(f"[!] Processed {i} rows in x509_certs...")

        print("[!] Processing the remaining data")
        for table in TABLES - {"x509_certs"}:
            process_rows(session, table, BATCH_SIZE, callback=queue_row)


if __name__ == "__main__":
    run()
