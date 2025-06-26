from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from datetime import datetime
import database as db  # ---------------- novo módulo

# ---------------
#  SERVIDOR CHAT
# ---------------
#  Agora persiste usuários e mensagens offline em SQLite (chat.db)
# --------------------------------------------------------------

class Servidor:
    def __init__(self, host='0.0.0.0', port=12345):
        self.host = host
        self.port = port

        # {nome: socket} – apenas usuários ONLINE
        self.clients = {}

        # inicializa BD
        db.init_db()

    # ---------- utilidades internas ---------- #
    def _broadcast_status(self, username: str, status: str):
        for sock in self.clients.values():
            try:
                sock.send(f"STATUS:{username}:{status}".encode('utf-8'))
            except Exception:
                pass

    def _send_contacts(self, client_socket):
        contatos = ','.join(db.list_users())
        client_socket.send(f"CONTACTS:{contatos}".encode('utf-8'))

    def _deliver_offline(self, username: str, client_socket):
        for sender, ts, txt in db.fetch_offline(username):
            client_socket.send(f"CHAT:{sender}:{ts}:{txt}".encode('utf-8'))

    # ---------- thread por cliente ---------- #
    def handle_client(self, client_socket):
        while True:
            client_name = client_socket.recv(1024).decode('utf-8').strip()
            if not client_name:
                client_socket.close()
                return

            if client_name in self.clients:
                client_socket.send("Nome já conectado. Tente outro.".encode('utf-8'))
                continue

            # Grava usuário no banco (caso seja novo)
            db.add_user(client_name)

            self.clients[client_name] = client_socket
            client_socket.send("Nome aceito".encode('utf-8'))
            print(f"[*] Cliente {client_name} conectado")
            break

        self._send_contacts(client_socket)
        self._deliver_offline(client_name, client_socket)
        self._broadcast_status(client_name, "ONLINE")

        while True:
            try:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    raise ConnectionResetError()

                if data.startswith("MSG:"):
                    _, dest, msg = data.split(":", 2)
                    timestamp = datetime.now().isoformat(timespec='seconds')
                    if dest in self.clients:
                        self.clients[dest].send(f"CHAT:{client_name}:{timestamp}:{msg}".encode('utf-8'))
                    else:
                        db.store_offline(client_name, dest, msg)
                        client_socket.send(f"SYSTEM:{dest} está offline. Mensagem armazenada.".encode('utf-8'))

                elif data.startswith("TYPING:"):
                    _, dest = data.split(":", 1)
                    if dest in self.clients:
                        self.clients[dest].send(f"TYPING:{client_name}".encode('utf-8'))

                elif data.strip() == "LIST":
                    self._send_contacts(client_socket)

            except Exception as e:
                print(f"[*] Cliente {client_name} desconectado: {e}")
                self.clients.pop(client_name, None)
                self._broadcast_status(client_name, "OFFLINE")
                client_socket.close()
                break

    # ---------- loop principal ---------- #
    def start(self):
        server = socket(AF_INET, SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen()
        print(f"[*] Ouvindo em {self.host}:{self.port}")

        while True:
            client_socket, addr = server.accept()
            print(f"[*] Conexão aceita de {addr}")
            Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()


if __name__ == "__main__":
    Servidor().start()
