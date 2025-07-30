from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from datetime import datetime
import database as db
from struct import unpack
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ SERVER.PY ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#  Parte responsável do código por ser o servidor da nossa plataforma! =D


#  ~~~~~~~~~~~~~~~~  Função para criar o nonce ~~~~~~~~~~~~~~~~~~~~
def gerar_nonce(tamanho=32):
    return os.urandom(tamanho)


class Servidor:
    def __init__(self, host='0.0.0.0', port=12345):
        self.host = host
        self.port = port

        #~~~~~~~~~~~~~~~~~~~  {nome: socket} – apenas usuários ONLINE ~~~~~~~~~~~~~~~~~~
        self.clients = {}

        # ~~~~~~~~~~~~~~~~~ inicializa o Banco de Dados ~~~~~~~~~~~~~~~~~~
        db.init_db()

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ UTILIDADES INTERNAS ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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
                print(f"[DEBUG] Enviando histórico: sender={sender}, ts={ts}, txt={txt}")
                client_socket.send(f"CHAT:{sender}:{ts}:{txt}".encode('utf-8'))
        except Exception as e:
            print(f"[!] Erro ao carregar histórico de {username}: {e}")

    # ~~~~~~~~~~~~~~~~~~~~~~~~~ THREAD POR CLIENTE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def handle_client(self, client_socket):
        """Lida com a conexão de um cliente individual."""
        client_name = None

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ LOOP DE AUTENTICAÇÃO ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        try:
            # ~~~~~~~~~~~~  1. Recebe o nome até encontrar quebra de linha ~~~~~~~~~~~~~~
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

            if db.username_exists(client_name): # ~~~~~~~~~~~~ Se o usuário existir ~~~~~~~~~~~~~~~~~~
                print(f"[*] Usuário '{client_name}' existe. Iniciando autenticação com nonce.")
                client_socket.send(b"L")  # ~~~~~~~~~~~~~~~~~ Identifica que é login (Inicia a autenticação) ~~~~~~~~~~~~~~~~~~~~

                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ AUTENTICAÇÃO ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                #  ~~~~~~~~~~~~~ 1. Função pra buscar a chave publica no banco de dados ~~~~~~~~~~~~~~~~~~~~
                print("[*] Buscando chave pública no banco de dados.")
                public_key_bytes = db.get_public_key(client_name)
                public_key = serialization.load_pem_public_key(public_key_bytes)

                # ~~~~~~~~~~~~~ 2. Função pra gerar e enviar o nonce ~~~~~~~~~~~~~~~~
                nonce = gerar_nonce()
                print(f"[*] Nonce gerado (tamanho {len(nonce)} bytes). Enviando para o cliente.")
                client_socket.send(len(nonce).to_bytes(2, byteorder='big') + nonce)

                # ~~~~~~~~~~~~~~~~~~ 3. Recebe a assinatura do nonce (tamanho + conteúdo) ~~~~~~~~~~~~~~~~~~~~
                assinatura_len_bytes = client_socket.recv(2)
                assinatura_len = int.from_bytes(assinatura_len_bytes, byteorder='big')
                assinatura = client_socket.recv(assinatura_len)
                print(f"[*] Assinatura recebida ({assinatura_len} bytes). Verificando...")

                # ~~~~~~~~~~~~~~~~~~~~~~~ 4. Verifica a assinatura ~~~~~~~~~~~~~~~~~~~~~~~~~~
                try:
                    public_key.verify(
                        assinatura,
                        nonce,
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                    # ~~~~~~~~~~~~~~~~~~~ Se funcionar, entra corretamente ~~~~~~~~~~~~~~~~~~~~~~
                    print("[+] Assinatura válida! Usuário autenticado com sucesso.")
                    client_socket.send("Nome aceito".encode('utf-8'))
                    self.clients[client_name] = client_socket
                    print(f"[*] Cliente {client_name} autenticado e conectado")
                except Exception:
                    client_socket.send("Assinatura inválida. Conexão negada.".encode('utf-8'))
                    client_socket.close()
                    return

            else:
                print(f"[*] Usuário '{client_name}' não existe. Registrando novo usuário.")
                client_socket.send(b"R")
                # ~~~~~~~~~~~~~~~~~ 1. Recebe 4 bytes indicando o tamanho da chave pública ~~~~~~~~~~~~~~~~~~~~
                key_size_bytes = client_socket.recv(4)
                if len(key_size_bytes) < 4:
                    client_socket.close()
                    return
                key_size = int.from_bytes(key_size_bytes, byteorder='big')

                # ~~~~~~~~~~~~~~~~~~~~~~  2. Recebe exatamente key_size bytes da chave pública ~~~~~~~~~~~~~~~~~~~~~~~~
                print(f"[*] Recebendo chave pública do cliente ({key_size} bytes).")
                public_key = b''
                while len(public_key) < key_size:
                    chunk = client_socket.recv(key_size - len(public_key))
                    if not chunk:
                        client_socket.close()
                        return
                    public_key += chunk

                # ~~~~~~~~~~~~~~~ 3. Armazena no banco ~~~~~~~~~~~~~~~~~~~~~~~~
                print("[*] Salvando chave pública no banco de dados.")
                db.add_user(client_name, public_key)

                # ~~~~~~~~~~~~~~~~ 4. Aceita conexão ~~~~~~~~~~~~~~~~~~~~~~~~
                self.clients[client_name] = client_socket
                client_socket.send("Nome aceito".encode('utf-8'))
                print(f"[*] Cliente {client_name} registrado e conectado")

        except Exception as e:
            print(f"[!] Erro durante autenticação/registro: {e}")
            client_socket.close()
            return

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ FLUXO PÓS AUTENTICAÇÃO ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        # ~~~~~~~~~~~~~~~~~~ Envia lista de contatos ~~~~~~~~~~~~~~~~~~~~~~~~
        self._send_contacts(client_socket)

        # ~~~~~~~~~~~~~~~~~~~ Envia as mensagens enviadas em quanto o usuário estava offline ~~~~~~~~~~~~~~~~~~~~
        self._deliver_all_history(client_name, client_socket)

        # ~~~~~~~~~~~~~~~~~~~~  Avisa ao cliente quem já está online ~~~~~~~~~~~~~~~~~~~~
        for user in self.clients:
            if user != client_name:
                try:
                    client_socket.send(f"STATUS:{user}:ONLINE".encode('utf-8'))
                except Exception:
                    pass

        # ~~~~~~~~~~~~~~~~~~~ Avisa a todos que ele está online ~~~~~~~~~~~~~~~~~~~~~~~~
        self._broadcast_status(client_name, "ONLINE")

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Loop de recebimento ~~~~~~~~~~~~~~~~~~~~~~~~~~
        while True:
            try:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    raise ConnectionResetError()

                elif data.startswith("MSG:"):
                    try:
                        # Divide a mensagem em EXATAMENTE 4 partes
                        parts = data.split(":", 3)  # MSG:dest:timestamp:conteúdo
                        if len(parts) != 4:
                            print(f"[ERRO] Formato inválido: {data[:100]}...")
                            continue
                            
                        _, destinatario, timestamp, mensagem_cifrada = parts
                        
                        # Remove quaisquer \n extras no final
                        mensagem_cifrada = mensagem_cifrada.strip()
                        
                        print(f"[DEBUG] Mensagem recebida de {client_name} para {destinatario} (ts: {timestamp})")
                        
                        # Armazena no banco de dados (sem modificar a mensagem)
                        db.store_message(destinatario, client_name, timestamp, mensagem_cifrada)
                        
                        # Encaminha para o destinatário se estiver online
                        if destinatario in self.clients:
                            self.clients[destinatario].send(f"CHAT:{client_name}:{timestamp}:{mensagem_cifrada}\n".encode('utf-8'))
                            
                    except Exception as e:
                        print(f"[ERRO] Falha ao processar MSG: {e}")


                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Função responsável por fazer o intermédio entre as chaves publicas entre A e B ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                elif data.startswith("PUBKEY_REQUEST:"):
                    try:
                        _, target_username = data.strip().split(":", 1)
                        print(f"\n[*] {client_name} pediu a chave pública de {target_username}")
                        pubkey_bytes = db.get_public_key(target_username)
                        if pubkey_bytes:
                            pubkey_b64 = base64.b64encode(pubkey_bytes).decode('utf-8')
                            print(f"[+] Enviando chave pública de {target_username} para {client_name}: {pubkey_b64[:30]}... (total {len(pubkey_b64)} bytes)")
                            
                            client_socket.send(f"PUBKEY_RESPONSE:{target_username}:{pubkey_b64}".encode('utf-8'))

                        # ~~~~~~~~~~~~~~~~~~~~~~~~~ Função responsável por mostrar no terminal o nome do usuário A que quer conversar com B ~~~~~~~~~~~~~~~~~~~~~~~~~~
                            if target_username in self.clients:
                                self.clients[target_username].send(
                                    f"PUBKEY_NOTIFY:{client_name} quer conversar com você.".encode('utf-8')
                                )
                        else:
                            client_socket.send(f"SYSTEM:Usuário {target_username} não encontrado.".encode('utf-8'))
                    except Exception as e:
                        print(f"[!] Erro ao processar PUBKEY_REQUEST: {e}")

                elif data.startswith("TYPING:"):
                    _, dest = data.split(":", 1)
                    if dest in self.clients:

                        self.clients[dest].send(f"TYPING:{client_name}".encode('utf-8'))
                # ~~~~~~~~~~~~~~~~~~~~~~~ BLOCO PARA O ROTEAMENTO DAS CHAVES DH ~~~~~~~~~~~~~~~~~~~~~~~~
                elif data.startswith("DHE_INIT:"):
                    try:
                        _, dest, encrypted_dh_b64 = data.split(":", 2)
                        if dest in self.clients:
                            self.clients[dest].send(f"DHE_INIT:{client_name}:{encrypted_dh_b64}".encode('utf-8'))
                            print(f"[+] Roteando DHE_INIT de {client_name} para {dest}")
                        else:
                            client_socket.send(f"SYSTEM:{dest} está offline. Handshake não pode ser iniciado.".encode('utf-8'))
                    except Exception as e:
                        print(f"[!] Erro ao processar DHE_INIT: {e}")

                elif data.startswith("DHE_RESPONSE:"):
                    try:
                        _, dest, encrypted_dh_b64 = data.split(":", 2)
                        if dest in self.clients:
                            # repassa a resposta para o cliente que iniciou
                            self.clients[dest].send(f"DHE_RESPONSE:{client_name}:{encrypted_dh_b64}".encode('utf-8'))
                            print(f"[+] Roteando DHE_RESPONSE de {client_name} para {dest}")
                        else:
                            client_socket.send(f"SYSTEM:{dest} está offline. Handshake não pode ser finalizado.".encode('utf-8'))
                    except Exception as e:
                        print(f"[!] Erro ao processar DHE_RESPONSE: {e}")

                elif data.strip() == "LIST":
                    self._send_contacts(client_socket)

            except Exception as e:
                print(f"[*] Cliente {client_name} desconectado: {e}")
                self.clients.pop(client_name, None)
                self._broadcast_status(client_name, "OFFLINE")
                client_socket.close()
                break


    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~ LOOP PRINCIPAL ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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