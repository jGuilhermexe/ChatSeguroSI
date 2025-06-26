"""
database.py  –  Persistência em SQLite para o Chat

• Guarda usuários cadastrados
• Armazena mensagens pendentes quando o destinatário estiver off-line
"""

import sqlite3
from datetime import datetime
from contextlib import closing

DB_PATH = "chat.db"


def _get_conn():
    """Abre conexão (modo AUTOCOMMIT desabilitado)."""
    return sqlite3.connect(DB_PATH, check_same_thread=False)


# ---------- criação de tabelas, caso não existam ---------- #
def init_db():
    with _get_conn() as conn, closing(conn.cursor()) as cur:
        cur.execute(
            """CREATE TABLE IF NOT EXISTS users (
                   username TEXT PRIMARY KEY
               )"""
        )
        cur.execute(
            """CREATE TABLE IF NOT EXISTS messages (
                   id         INTEGER PRIMARY KEY AUTOINCREMENT,
                   sender     TEXT    NOT NULL,
                   recipient  TEXT    NOT NULL,
                   timestamp  TEXT    NOT NULL,
                   text       TEXT    NOT NULL
               )"""
        )
        conn.commit()


# ---------- usuários ---------- #
def add_user(username: str):
    with _get_conn() as conn, closing(conn.cursor()) as cur:
        cur.execute("INSERT OR IGNORE INTO users (username) VALUES (?)", (username,))
        conn.commit()


def list_users() -> list[str]:
    with _get_conn() as conn, closing(conn.cursor()) as cur:
        cur.execute("SELECT username FROM users ORDER BY username")
        return [row[0] for row in cur.fetchall()]


# ---------- mensagens offline ---------- #
def store_offline(sender: str, recipient: str, text: str):
    with _get_conn() as conn, closing(conn.cursor()) as cur:
        cur.execute(
            "INSERT INTO messages (sender, recipient, timestamp, text) "
            "VALUES (?,?,?,?)",
            (sender, recipient, datetime.now().isoformat(timespec="seconds"), text),
        )
        conn.commit()


def fetch_offline(recipient: str) -> list[tuple[str, str, str]]:
    """Retorna [(sender, timestamp, text), ...] e remove do banco."""
    with _get_conn() as conn, closing(conn.cursor()) as cur:
        cur.execute(
            "SELECT id, sender, timestamp, text FROM messages "
            "WHERE recipient=? ORDER BY id",
            (recipient,),
        )
        rows = cur.fetchall()
        ids = [row[0] for row in rows]
        if ids:
            cur.execute(
                f"DELETE FROM messages WHERE id IN ({','.join('?'*len(ids))})", ids
            )
            conn.commit()
        return [(row[1], row[2], row[3]) for row in rows]
