from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from datetime import datetime
import database as db
from struct import unpack

# ---------------
#  SERVIDOR CHAT
# ---------------

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
        """Envia atualização de status para todos os clientes online."""
        for sock in self.clients.values():
            try:
                sock.send(f"STATUS:{username}:{status}".encode('utf-8'))
            except Exception:
                pass

    def _send_contacts(self, client_socket):
        """Envia a lista de todos os usuários registrados para um cliente."""
        contatos = ','.join(db.list_users())
        client_socket.send(f"CONTACTS:{contatos}".encode('utf-8'))

    def _deliver_all_history(self, username: str, client_socket):
        """Envia TODO o histórico de mensagens para o usuário ao entrar."""
        try:
            messages = db.fetch_all_messages(username)
            for sender, ts, txt in messages:
                client_socket.send(f"CHAT:{sender}:{ts}:{txt}".encode('utf-8'))
        except Exception as e:
            print(f"[!] Erro ao carregar histórico de {username}: {e}")

    # ---------- thread por cliente ---------- #
    def handle_client(self, client_socket):
        """Lida com a conexão de um cliente individual."""
        client_name = None

        # --- LOOP DE AUTENTICAÇÃO ---
        try:
            # 1. Recebe o nome até encontrar quebra de linha
            temp_name = ""
            while not temp_name.endswith("\n"):
                temp_name += client_socket.recv(1).decode('utf-8')
            client_name = temp_name.strip()

            if not client_name:
                client_socket.close()
                return

            if client_name in self.clients:
                client_socket.send("Nome já conectado. Tente outro.".encode('utf-8'))
                return
            if db.username_exists(temp_name):
                client_socket.send("Nome já registrado. Use outro nome.".encode('utf-8'))
                client_socket.close()
                return

            # 2. Recebe 4 bytes indicando o tamanho da chave pública
            key_size_bytes = client_socket.recv(4)
            if len(key_size_bytes) < 4:
                client_socket.close()
                return
            key_size = int.from_bytes(key_size_bytes, byteorder='big')

            # 3. Recebe exatamente key_size bytes da chave pública
            public_key = b''
            while len(public_key) < key_size:
                chunk = client_socket.recv(key_size - len(public_key))
                if not chunk:
                    client_socket.close()
                    return
                public_key += chunk

            # 4. Armazena no banco
            db.add_user(client_name, public_key)

            # 5. Aceita conexão
            self.clients[client_name] = client_socket
            client_socket.send("Nome aceito".encode('utf-8'))
            print(f"[*] Cliente {client_name} conectado")

        except Exception as e:
            print(f"[!] Erro durante autenticação de cliente: {e}")
            client_socket.close()
            return

        # --- FLUXO PÓS-AUTENTICAÇÃO ---

        # Envia lista de contatos
        self._send_contacts(client_socket)

        # Envia mensagens offline
        self._deliver_all_history(client_name, client_socket)

        # Avisa ao cliente quem já está online
        for user in self.clients:
            if user != client_name:
                try:
                    client_socket.send(f"STATUS:{user}:ONLINE".encode('utf-8'))
                except Exception:
                    pass

        # Avisa a todos que ele está online
        self._broadcast_status(client_name, "ONLINE")

        # Loop de recebimento
        while True:
            try:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    raise ConnectionResetError()

                if data.startswith("MSG:"):
                    _, dest, msg = data.split(":", 2)
                    timestamp = datetime.now().isoformat(timespec='seconds')
                    db.store_message(dest, client_name, timestamp, msg)

                    if dest in self.clients:
                        self.clients[dest].send(f"CHAT:{client_name}:{timestamp}:{msg}".encode('utf-8'))
                    else:
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
        """Inicia o servidor e aguarda por conexões."""
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