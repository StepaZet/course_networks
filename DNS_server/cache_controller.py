import sqlite3
import time


class DNSCacheController:
    def __init__(self, name: str):
        self.name = name
        self.conn = sqlite3.connect(f'{name}.db')
        self.cursor = self.conn.cursor()
        self.cursor.execute(f'''CREATE TABLE IF NOT EXISTS {name} (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                domain TEXT,
                                data BLOB,
                                ttl INTEGER,
                                time_create REAL)''')

    def add_domain(self, domain: str, data: bytes, ttl: int) -> None:
        self.cursor.execute(f"INSERT INTO {self.name} "
                            f"(domain, data, ttl, time_create) "
                            f"VALUES (?, ?, ?, ?)",
                            (domain, data, ttl, time.time()))
        self.conn.commit()

    def delete_domain(self, domain: str) -> None:
        self.cursor.execute(f"DELETE FROM {self.name} "
                            f"WHERE domain = ?", (domain,))
        self.conn.commit()

    def get_data(self, domain: str) -> bytes:
        self.cursor.execute(f"SELECT * FROM {self.name} "
                            f"WHERE domain = ?", (domain,))
        return self.cursor.fetchone()[2]

    def is_domain_in_cache(self, domain: str) -> bool:
        self.cursor.execute(f"SELECT * FROM {self.name} "
                            f"WHERE domain = ?", (domain,))
        return self.cursor.fetchone() is not None

    def get_domain_age(self, domain: str) -> float:
        self.cursor.execute(f"SELECT * FROM {self.name} "
                            f"WHERE domain = ?", (domain,))
        data = self.cursor.fetchone()
        return time.time() - data[4]

    def is_domain_valid(self, domain: str) -> bool:
        self.cursor.execute(f"SELECT * FROM {self.name} "
                            f"WHERE domain = ?", (domain,))
        data = self.cursor.fetchone()
        if data is None:
            return False
        if time.time() - data[4] > data[3]:
            return False
        return True
