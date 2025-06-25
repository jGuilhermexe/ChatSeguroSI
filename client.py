from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
import sys
import time

# -------------
#  CLIENTE CHAT
# -------------
# – Conecta ao servidor, escolhe um nome
# – Possui thread para receber dados e thread principal para enviar
# – Suporta:
#     • lista de contatos
#     • envio de mensagens
#     • indicador de “digitando…”
#     • exibe status online/off-line
# -----------------------------------------------

class Cliente:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.name = None
        self.contatos = []          # lista de todos os usuários

    # ---------- recepção assíncrona ---------- #
    def _receive_loop(self):
        while True:
            try:
                data = self.sock.recv(4096).decode('utf-8')
                if not data:
                    raise ConnectionResetError()

                # ------------------------------
                # Tipos de pacotes recebidos:
                #   CHAT:<remetente>:<timestamp>:<texto>
                #   TYPING:<remetente>
                #   STATUS:<usuario>:<ONLINE|OFFLINE>
                #   CONTACTS:userA,userB,...
                #   SYSTEM:<mensagem informativa>
                # ------------------------------
                if data.startswith("CHAT:"):
                    _, sender, ts, txt = data.split(":", 3)
                    print(f"\n[{ts}] {sender}: {txt}")

                elif data.startswith("TYPING:"):
                    _, who = data.split(":", 1)
                    print(f"\n*** {who} está digitando...")

                elif data.startswith("STATUS:"):
                    _, user, st = data.split(":", 2)
                    print(f"\n*** {user} ficou {st.lower()}")

                elif data.startswith("CONTACTS:"):
                    _, lista = data.split(":", 1)
                    self.contatos = lista.split(",") if lista else []
                    print("\n*** Contatos atualizados:", ", ".join(self.contatos))

                elif data.startswith("SYSTEM:"):
                    print("\n(!)", data.replace("SYSTEM:", ""))

                # Mantém prompt limpo
                print("> ", end='', flush=True)

            except Exception as e:
                print("\n[!] Conexão perdida:", e)
                self.sock.close()
                sys.exit(1)

    # ---------- envio interativo ---------- #
    def _send_loop(self):
        while True:
            try:
                dest = input("Destinatário (LIST para ver contatos): ").strip()

                if dest.upper() == "LIST":
                    self.sock.send("LIST".encode('utf-8'))
                    continue

                # envia evento de digitação ANTES da mensagem (visual)
                self.sock.send(f"TYPING:{dest}".encode('utf-8'))

                msg = input("Mensagem (vazio para cancelar): ").rstrip()
                if not msg:
                    continue   # cancela

                self.sock.send(f"MSG:{dest}:{msg}".encode('utf-8'))

            except KeyboardInterrupt:
                print("\n[!] Encerrando.")
                self.sock.close()
                sys.exit(0)
            except Exception as e:
                print("[Erro]", e)
                self.sock.close()
                sys.exit(1)

    # ---------- autenticação simples ---------- #
    def _login(self):
        while True:
            self.name = input("Informe seu nome: ").strip()
            if not self.name:
                continue
            self.sock.send(self.name.encode('utf-8'))
            resposta = self.sock.recv(1024).decode('utf-8')
            if resposta == "Nome aceito":
                print("[*] Nome aceito, entrando no chat…")
                break
            else:
                print(resposta)

    # ---------- fluxo principal ---------- #
    def start(self):
        self.sock.connect((self.host, self.port))
        print("[*] Conectado ao servidor.")

        self._login()

        # thread secundária para receber dados
        Thread(target=self._receive_loop, daemon=True).start()

        # thread principal → envio
        self._send_loop()


if __name__ == "__main__":
    Cliente().start()
