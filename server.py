from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from datetime import datetime

# ---------------
#  SERVIDOR CHAT
# ---------------
# – Aceita múltiplos clientes simultaneamente (threads)
# – Cada cliente se identifica com um nome único
# – Mantém uma lista completa de usuários já registrados
# – Encaminha mensagens em tempo real
# – Armazena mensagens caso o destinatário esteja offline
# – Envia eventos de digitação e status online/off-line
#
#  IMPORTANTE:
#  • Esta versão guarda dados apenas em memória.
#    Para persistir após reiniciar o servidor, use SQLite ou outro BD leve.
# ------------------------------------------------------

class Servidor:
    def __init__(self, host='0.0.0.0', port=12345):
        self.host = host
        self.port = port

        # {nome: socket} – apenas usuários ONLINE
        self.clients = {}

        # {nome: True}   – todos os usuários já registrados (online ou offline)
        self.registered_users = {}

        # {destinatário: [(remetente, mensagem, timestamp), ...]}
        self.offline_messages = {}

    # ---------- utilidades internas ---------- #
    def _broadcast_status(self, username: str, status: str) -> None:
        """
        Envia para todos os clientes online a mudança de status:
        STATUS:<usuario>:<ONLINE|OFFLINE>
        """
        for sock in self.clients.values():
            try:
                sock.send(f"STATUS:{username}:{status}".encode('utf-8'))
            except Exception:
                pass  # se falhar, será tratado em outro ponto

    def _send_contacts(self, client_socket) -> None:
        """
        Envia a lista completa de contatos ao cliente recém-logado.
        Formato: CONTACTS:user1,user2,user3
        """
        contatos = ','.join(self.registered_users.keys())
        client_socket.send(f"CONTACTS:{contatos}".encode('utf-8'))

    def _deliver_offline(self, username: str, client_socket) -> None:
        """
        Entrega mensagens armazenadas enquanto o usuário estava offline.
        """
        msgs = self.offline_messages.pop(username, [])
        for sender, txt, ts in msgs:
            client_socket.send(f"CHAT:{sender}:{ts}:{txt}".encode('utf-8'))

    # ---------- thread por cliente ---------- #
    def handle_client(self, client_socket):
        """
        1) Autentica/Registra o nome
        2) Entrega lista de contatos e mensagens offline
        3) Entra no loop principal de recepção
        """
        # 1) REGISTRO/AUTENTICAÇÃO SIMPLES
        while True:
            client_name = client_socket.recv(1024).decode('utf-8').strip()
            if not client_name:
                client_socket.close()
                return

            # Nome já em uso na sessão atual?
            if client_name in self.clients:
                client_socket.send("Nome já conectado. Tente outro.".encode('utf-8'))
                continue

            # Nome OK → registra se for a primeira vez
            self.registered_users[client_name] = True
            self.clients[client_name] = client_socket
            client_socket.send("Nome aceito".encode('utf-8'))
            print(f"[*] Cliente {client_name} conectado")
            break

        # 2) CONTATOS + MENSAGENS OFFLINE + STATUS BROADCAST
        self._send_contacts(client_socket)
        self._deliver_offline(client_name, client_socket)
        self._broadcast_status(client_name, "ONLINE")

        # 3) LOOP PRINCIPAL
        while True:
            try:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    raise ConnectionResetError()

                # --------------------------------------------------
                # FORMATO DOS PACOTES (lado do cliente)
                #   MSG:<destinatario>:<mensagem>
                #   TYPING:<destinatario>
                #   LIST                 -> pedir contatos de novo
                # --------------------------------------------------
                if data.startswith("MSG:"):
                    _, dest, msg = data.split(":", 2)
                    timestamp = datetime.now().isoformat(timespec='seconds')
                    if dest in self.clients:          # destinatário ONLINE
                        self.clients[dest].send(f"CHAT:{client_name}:{timestamp}:{msg}".encode('utf-8'))
                    else:                             # OFFLINE → guarda
                        self.offline_messages.setdefault(dest, []).append(
                            (client_name, msg, timestamp)
                        )
                        client_socket.send(f"SYSTEM:{dest} está offline. Mensagem armazenada.".encode('utf-8'))

                elif data.startswith("TYPING:"):
                    _, dest = data.split(":", 1)
                    if dest in self.clients:
                        self.clients[dest].send(f"TYPING:{client_name}".encode('utf-8'))

                elif data.strip() == "LIST":
                    self._send_contacts(client_socket)

            except Exception as e:
                # Conexão encerrada ou erro
                print(f"[*] Cliente {client_name} desconectado: {e}")
                self.clients.pop(client_name, None)
                self._broadcast_status(client_name, "OFFLINE")
                client_socket.close()
                break

    # ---------- loop principal do servidor ---------- #
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
