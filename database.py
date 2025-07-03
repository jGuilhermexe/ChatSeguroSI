import sqlite3
from datetime import datetime

DB_PATH = "chat.db"

# ---------- inicializa estrutura do banco ---------- #
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Tabela de usuários
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            nome TEXT PRIMARY KEY
        )
    """)

    # Tabela de mensagens offline
    cur.execute("""
        CREATE TABLE IF NOT EXISTS mensagens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remetente TEXT NOT NULL,
            destinatario TEXT NOT NULL,
            texto TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# ---------- adiciona novo usuário (se ainda não existir) ---------- #
def add_user(nome: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO usuarios (nome) VALUES (?)", (nome,))
    conn.commit()
    conn.close()

# ---------- lista todos os usuários registrados ---------- #
def list_users():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT nome FROM usuarios")
    nomes = [row[0] for row in cur.fetchall()]
    conn.close()
    return nomes

# ---------- armazena mensagem offline ---------- #
def store_offline(remetente: str, destinatario: str, texto: str):
    ts = datetime.now().isoformat(timespec='seconds')
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO mensagens (remetente, destinatario, texto, timestamp)
        VALUES (?, ?, ?, ?)
    """, (remetente, destinatario, texto, ts))
    conn.commit()
    conn.close()

# ---------- busca e remove mensagens offline para um destinatário ---------- #
def fetch_offline(destinatario: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Busca mensagens
    cur.execute("""
        SELECT remetente, timestamp, texto
        FROM mensagens
        WHERE destinatario = ?
        ORDER BY timestamp ASC
    """, (destinatario,))
    mensagens = cur.fetchall()

    # Apaga mensagens entregues
    cur.execute("DELETE FROM mensagens WHERE destinatario = ?", (destinatario,))
    conn.commit()
    conn.close()

    return mensagens
