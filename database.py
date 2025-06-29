import sqlite3
from datetime import datetime

DB_PATH = "chat.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mensagens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remetente TEXT NOT NULL,
            mensagem TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def salvar_mensagem(remetente, mensagem):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO mensagens (remetente, mensagem, timestamp) VALUES (?, ?, ?)",
                   (remetente, mensagem, datetime.now()))
    conn.commit()
    conn.close()

def buscar_ultimas_mensagens(limit=50):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT remetente, mensagem, timestamp FROM mensagens ORDER BY timestamp DESC LIMIT ?", (limit,))
    resultados = cursor.fetchall()
    conn.close()
    return list(reversed(resultados))
