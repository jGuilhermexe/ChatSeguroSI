import sqlite3
from datetime import datetime
from contextlib import closing

DB_PATH = "chat.db"

def _get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

# Criação das tabelas do banco de dados
def init_db():
    with _get_conn() as conn, closing(conn.cursor()) as cur:
        cur.execute(
            """CREATE TABLE IF NOT EXISTS users (
                   username TEXT PRIMARY KEY
               )"""
        )
        conn.commit()

# Adicionando usuários a tabela
def add_user(username: str):
    with _get_conn() as conn, closing(conn.cursor()) as cur:
        cur.execute("INSERT OR IGNORE INTO users (username) VALUES (?)", (username,))
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS messages_{username} (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                sender     TEXT    NOT NULL,
                timestamp  TEXT    NOT NULL,
                text       TEXT    NOT NULL
            )
        """)
        conn.commit()

# Listando usuários 
def list_users() -> list[str]:
    with _get_conn() as conn, closing(conn.cursor()) as cur:
        cur.execute("SELECT username FROM users ORDER BY username")
        return [row[0] for row in cur.fetchall()]

# Salvando mensagens em quanto os usuários estão offline
def store_offline(sender: str, recipient: str, text: str):
    with _get_conn() as conn, closing(conn.cursor()) as cur:
        cur.execute(f"""
            INSERT INTO messages_{recipient} (sender, timestamp, text)
            VALUES (?, ?, ?)
        """, (sender, datetime.now().isoformat(timespec="seconds"), text))
        conn.commit()

def fetch_offline(recipient: str) -> list[tuple[str, str, str]]:
    with _get_conn() as conn, closing(conn.cursor()) as cur:
        cur.execute(f"""
            SELECT id, sender, timestamp, text FROM messages_{recipient} ORDER BY id
        """)
        rows = cur.fetchall()
        ids = [row[0] for row in rows]
        if ids:
            cur.execute(f"""
                DELETE FROM messages_{recipient} WHERE id IN ({','.join('?'*len(ids))})
            """, ids)
            conn.commit()
        return [(row[1], row[2], row[3]) for row in rows]


 # Armazenar todo o histórico de mensagens no chat   
def store_message(recipient: str, sender: str, timestamp: str, text: str):
    with _get_conn() as conn, closing(conn.cursor()) as cur:
        cur.execute(f"""
            INSERT INTO messages_{recipient} (sender, timestamp, text)
            VALUES (?, ?, ?)
        """, (sender, timestamp, text))
        conn.commit()
def fetch_all_messages(recipient: str) -> list[tuple[str, str, str]]:
    with _get_conn() as conn, closing(conn.cursor()) as cur:
        cur.execute(f"""
            SELECT sender, timestamp, text FROM messages_{recipient} ORDER BY id
        """)
        return cur.fetchall()
