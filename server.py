from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from datetime import datetime
import database as db

# ---------------
#  SERVIDOR CHAT
# ---------------
#  Agora persiste usuários e mensagens offline em SQLite (chat.db)
# --------------------------------------------------------------

class Servidor:
    def __init__(self, host='0.0.0.0', port=12345):
        self.host = host
        self.port = port

        # {nome: socket} – apenas usuários ONLINE
        self.clients = {}

        # inicializa BD
        db.init_db()

    # Alteração no método para criação do banco de dados para incluir a chave pública
    def init_db():
        with _get_conn() as conn, closing(conn.cursor()) as cur:
            cur.execute(
                """CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    public_key BLOB
                )"""
            )
            conn.commit()
        

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
        client_name = None # Inicializa o nome do cliente
    # Loop de autenticação
        while True:
            try:
                temp_name = client_socket.recv(1024).decode('utf-8').strip()
                if not temp_name:
                    client_socket.close()
                    return

                if temp_name in self.clients:
                    client_socket.send("Nome já conectado. Tente outro.".encode('utf-8'))
                    continue

                client_name = temp_name
                 # Recebendo a chave pública do cliente
                public_key = client_socket.recv(4096)

                db.add_user(client_name, public_key)  # Adiciona o usuário e a chave pública

                self.clients[client_name] = client_socket
                client_socket.send("Nome aceito".encode('utf-8'))
                print(f"[*] Cliente {client_name} conectado")
                break
            except ConnectionResetError:
                print("[*] Cliente desconectou antes de logar.")
                client_socket.close()
                return


        # --- Fluxo pós-autenticação ---
        
        # 1. Envia a lista de contatos completa
        self._send_contacts(client_socket)
        
        # 2. Envia as mensagens que estavam offline
        self._deliver_all_history(client_name, client_socket)

        #    Avisa ao novo cliente quem já está online.
        for user in self.clients:
            if user != client_name: # Para cada outro usuário que já está online...
                try:
                    # ...envia o status "ONLINE" para o cliente que acabou de conectar.
                    client_socket.send(f"STATUS:{user}:ONLINE".encode('utf-8'))
                except Exception as e:
                    print(f"[!] Erro ao enviar status de {user} para {client_name}: {e}")

        # 4. Avisa a todos (inclusive ao novo cliente) que ele ficou online.
        self._broadcast_status(client_name, "ONLINE")

        # Loop de recebimento de mensagens
        while True:
            try:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    raise ConnectionResetError()

                if data.startswith("MSG:"):
                    _, dest, msg = data.split(":", 2)
                    timestamp = datetime.now().isoformat(timespec='seconds')

                    # ✅ Sempre armazena a mensagem no banco, independentemente do status
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