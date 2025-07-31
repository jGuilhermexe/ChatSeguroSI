import customtkinter as ctk
from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
import sys
import queue
from PIL import Image
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding, hashes, hmac
import hmac as stdlib_hmac
import os
import base64
import traceback
from datetime import datetime



# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ GUI_CLIENT.PY ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Essa parte do código é responsável pelo design da interface gráfica e também da lógica.

def cifrar_mensagem(message, aes_key, hmac_key):
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Calcula HMAC sobre IV + ciphertext
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(iv + ciphertext)
    hmac_value = h.finalize()

    print("\n\n=============================================")
    print("\n[DEBUG - CIFRAR]")
    print("Mensagem original:", message)
    print("IV:", iv.hex())
    print("Ciphertext:", ciphertext.hex())
    print("HMAC gerado:", hmac_value.hex())
    print("HMAC key usada:", hmac_key.hex())
    print("AES key usada :", aes_key.hex())
    print("=============================================")
    # Retorna base64(IV + ciphertext + HMAC)
    return base64.b64encode(iv + ciphertext + hmac_value).decode('utf-8')


def decifrar_mensagem(encrypted_b64, aes_key, hmac_key):
    try:
        print("\n[DEBUG DECIFRAR]")
        print(f"Chave AES usada: {aes_key.hex()}")
        print(f"Chave HMAC usada: {hmac_key.hex()}")
        print(f"Base64 recebido: {encrypted_b64[:50]}... (tamanho: {len(encrypted_b64)})")
        
        # 1. Pré-processamento do Base64
        encrypted_b64 = encrypted_b64.split(":")[-1]
        print("[DEBUG] Base64 após strip:", repr(encrypted_b64))
        
        # 2. Verificação básica do tamanho
        if len(encrypted_b64) < 44:  # IV(16) + HMAC(32) + mínimo 1 byte de ciphertext
            raise ValueError("Payload cifrado muito curto para ser válido")

        # 3. Adicionar padding se necessário (Base64 deve ter comprimento múltiplo de 4)
        padding_needed = len(encrypted_b64) % 4
        if padding_needed:
            print(f"[DEBUG] Adicionando {4-padding_needed} caracteres de padding")
            encrypted_b64 += '=' * (4 - padding_needed)

        # 4. Decodificação Base64
        try:
            raw = base64.b64decode(encrypted_b64)
        except Exception as e:
            print(f"[!!!] Falha ao decodificar Base64: {e}")
            print("[DEBUG] Base64 problemático:", encrypted_b64)
            raise ValueError("Base64 inválido") from e

        print("[DEBUG] Tamanho após decodificação:", len(raw))
        
        # 5. Verificação do tamanho mínimo dos dados
        if len(raw) < 48:  # IV(16) + HMAC(32)
            raise ValueError("Dados decodificados insuficientes")

        # 6. Extração de IV, ciphertext e HMAC
        iv = raw[:16]
        ciphertext = raw[16:-32]  
        recv_hmac = raw[-32:]    
        
        print("\n\n=============================================")
        print("[DEBUG - DECIFRAR]")
        print("IV:", iv.hex())
        print("Ciphertext:", ciphertext.hex() if ciphertext else "VAZIO")
        print("HMAC recebido:", recv_hmac.hex())
        print("HMAC key usada:", hmac_key.hex())
        print("AES key usada:", aes_key.hex())
        print("=============================================")

        # 7. Verificação do HMAC
        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(iv + ciphertext)
        expected_hmac = h.finalize()
        
        print("HMAC esperado:", expected_hmac.hex())

        if not stdlib_hmac.compare_digest(expected_hmac, recv_hmac):
            print("[!!!] HMAC inválido - possível manipulação da mensagem!")
            raise ValueError("Falha na verificação de integridade (HMAC)")

        # 8. Decifração AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        try:
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            print(f"[!!!] Erro ao decifrar: {e}")
            raise ValueError("Decifração falhou") from e

        # 9. Remoção do padding PKCS7
        unpadder = sym_padding.PKCS7(128).unpadder()
        
        try:
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        except ValueError as e:
            print(f"[!!!] Erro ao remover padding: {e}")
            raise ValueError("Padding inválido") from e

        # 10. Decodificação UTF-8
        try:
            mensagem_decifrada = plaintext.decode('utf-8')
        except UnicodeDecodeError as e:
            print(f"[!!!] Erro ao decodificar UTF-8: {e}")
            raise ValueError("Mensagem decifrada não é UTF-8 válido") from e

        print("[✓] Mensagem decifrada com sucesso!")
        return mensagem_decifrada

    except Exception as e:
        print(f"[!!!] Erro crítico em decifrar_mensagem: {type(e).__name__}: {e}")
        traceback.print_exc()
        raise  # Re-lança a exceção para tratamento superior

# Função para gerar par de chaves RSA, colocando antes da classChatClient pra evitar qualquer tipo de conflito.
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
        
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
        )
        
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
    return private_pem, public_pem

with open("dh_params.pem", "rb") as f:
    DH_PARAMETERS = serialization.load_pem_parameters(f.read(), backend=default_backend())


def generate_dh_key_pair():
    """Gera uma chave efêmera DH (Diffie-Hellman)"""
    private_key = DH_PARAMETERS.generate_private_key()
    public_key = private_key.public_key()
    
    # Serializa a chave pública para enviar ao outro usuário
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key, public_bytes

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ LÓGICA: A classe ChatClient é responsável pela lógica da conexão da rede ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
class ChatClient:
    """Lógica de Rede do Cliente (Refatorada)"""
    def __init__(self, app_controller):
        self.session_keys = {}  # dicionário para guardar AES/HMAC/salt por contato
        self.peer_dh_keys = {}
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.app = app_controller
        self.buffer = ""
        self.COMMAND_PREFIXES = ["CHAT:", "TYPING:", "STATUS:", "CONTACTS:", "SYSTEM:", "PUBKEY_RESPONSE:", "PUBKEY_NOTIFY:", "DHE_INIT:", "DHE_RESPONSE:"]


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Função de conexão da plataforma ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def connect(self, host, port, username, public_key):
        try:
            print("[*] Conectando ao servidor...")
            self.sock.connect((host, port))
            print("[*] Conectado ao servidor.")

            print("[*] Enviando nome de usuário ao servidor.")
            self.sock.sendall((username + "\n").encode('utf-8'))

            tipo_conexao = self.sock.recv(1)
            if not tipo_conexao:
                self.app.on_login_fail("Falha ao se comunicar com o servidor.")
                return False

            if tipo_conexao == b"L":
               # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ FUNÇÃO RESPONSÁVEL PELO LOGIN NA PALTAFORMA ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                nonce_len = int.from_bytes(self.sock.recv(2), byteorder='big')
                nonce = self.sock.recv(nonce_len)

                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Faz o carregamento da chave privada ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                try:
                    with open(f"chaves/{username}_private_key.pem", "rb") as f:
                        private_key = serialization.load_pem_private_key(
                            f.read(),
                            password=None,
                            backend=default_backend()
                        )
                except Exception as e:
                    self.app.on_login_fail(f"Erro ao carregar chave privada: {e}")
                    return False

                assinatura = private_key.sign(
                    nonce,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )

                self.sock.sendall(len(assinatura).to_bytes(2, byteorder='big') + assinatura)
            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ FUNÇÃO RESPONSÁVEL PELO REGISTRO NA PLATAFORMA ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            elif tipo_conexao == b"R":
                self.sock.sendall(len(public_key).to_bytes(4, byteorder='big'))
                self.sock.sendall(public_key)
            else:
                self.app.on_login_fail("Resposta inválida do servidor.")
                return False
            # AGUARDA A RESPOSTA DO SERVIDOR
            response = self.sock.recv(1024).decode('utf-8')

            if response == "Nome aceito":
                self.app.on_login_success()
                Thread(target=self._receive_loop, daemon=True).start()
                return True
            else:
                self.app.on_login_fail(response)
                self.sock.close()
                self.sock = socket(AF_INET, SOCK_STREAM)
                return False
        except Exception as e:
            self.app.on_login_fail(f"Erro ao conectar: {e}")
            return False
        
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ LOGICA DE CONEXÃO DA PLATAFORMA ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    def send_message(self, recipient, message):
        try:
            if not hasattr(self, 'session_keys'):
                print(f"[!] Nenhuma sessão estabelecida com {recipient}. Não é possível enviar mensagem segura.")
                return

            if recipient not in self.session_keys:
                print(f"[!] Nenhuma sessão estabelecida com {recipient}. Iniciando handshake...")
                self.initiate_handshake(recipient)
                return

            session = self.session_keys[recipient]
            
            if "aes" not in session or "hmac" not in session:
                print(f"[!] Handshake com {recipient} ainda não finalizado. Não é possível enviar mensagem.")
                # Tenta reiniciar o handshake se estiver demorando muito
                if "handshake_time" not in session or (datetime.now() - session["handshake_time"]).seconds > 10:
                    print(f"[!] Reiniciando handshake com {recipient}...")
                    session["handshake_time"] = datetime.now()
                    self.initiate_handshake(recipient)
                return

            # Remove quebras de linha e espaços extras da mensagem
            message = message.strip()
            if not message:
                print("[!] Mensagem vazia ignorada.")
                return

            print(f"[DEBUG] Preparando para cifrar mensagem para {recipient}")
            encrypted_payload = cifrar_mensagem(message, session["aes"], session["hmac"])
            
            # Garante que o payload não contenha caracteres que possam quebrar o protocolo
            encrypted_payload = encrypted_payload.replace('\n', '').replace('\r', '').replace(':', '')
            
            timestamp = datetime.now().isoformat(timespec='seconds')
            protocol_message = f"MSG:{recipient}:{timestamp}:{encrypted_payload}\n"
            
            print(f"[DEBUG] Enviando mensagem cifrada para {recipient}")
            print(f"[DEBUG] Tamanho do payload: {len(encrypted_payload)} caracteres")
            
            try:
                self.sock.sendall(protocol_message.encode('utf-8'))
                print(f"[✓] Mensagem para {recipient} enviada com sucesso.")
            except Exception as send_error:
                print(f"[!] Erro ao enviar mensagem para {recipient}: {send_error}")
                # Tenta reconectar se houver erro de conexão
                if isinstance(send_error, (ConnectionResetError, BrokenPipeError)):
                    self.app.incoming_queue.put("SYSTEM:CONEXAO_PERDIDA")

        except Exception as e:
            print(f"[!!!] Erro crítico em send_message: {e}")
            traceback.print_exc()

    def send_typing_notification(self, recipient):
        try:
            self.sock.send(f"TYPING:{recipient}".encode('utf-8'))
        except Exception as e:
            print(f"[!] Erro ao enviar status 'digitando': {e}")
            
    def request_contact_list(self):
        try:
            self.sock.send("LIST".encode('utf-8'))
        except Exception as e:
            print(f"[!] Erro ao requisitar contatos: {e}")
    
    def _process_buffer(self):
        while True:
            first_msg_start = -1
            for prefix in self.COMMAND_PREFIXES:
                pos = self.buffer.find(prefix)
                if pos != -1 and (first_msg_start == -1 or pos < first_msg_start):
                    first_msg_start = pos

            if first_msg_start == -1:
                return

            if first_msg_start > 0:
                self.buffer = self.buffer[first_msg_start:]

            next_msg_start = -1
            # Aqui buscamos o próximo prefixo conhecido a partir de 1 após o início atual
            for prefix in self.COMMAND_PREFIXES:
                pos = self.buffer.find(prefix, first_msg_start + 1)
                if pos != -1 and (next_msg_start == -1 or pos < next_msg_start):
                    next_msg_start = pos

            if next_msg_start != -1:
                message = self.buffer[:next_msg_start]
                self.buffer = self.buffer[next_msg_start:]
                self.app.incoming_queue.put(message.strip())
            else:
                # Nenhum prefixo futuro encontrado; mensagem completa é tudo o que sobrou
                message = self.buffer
                self.buffer = ""
                self.app.incoming_queue.put(message.strip())
                break

    def _receive_loop(self):
        while True:
            try:
                data = self.sock.recv(4096).decode('utf-8')
                #print("[RECV] Data recebida do servidor:", repr(data))
                if not data:
                    raise ConnectionResetError()
                
                self.buffer += data
                self._process_buffer()

            except Exception as e:
                print(f"\n[!] Conexão perdida: {e}")
                self.app.incoming_queue.put(f"SYSTEM:CONEXAO_PERDIDA")
                self.sock.close()
                break


# ~~~~~~~~~~~~~~~~~~~~~~~~ LÓGICA - Cliente requisita ao servidor a chave publica entre cliente A e B ~~~~~~~~~~~~~~~~~~~~~~
    def request_public_key(self, username):
        try:
            print(f"\n[*] Cliente está pedindo ao servidor a chave pública de '{username}'...")
            self.sock.send(f"PUBKEY_REQUEST:{username}".encode('utf-8'))
        except Exception as e:
            print(f"[!] Erro ao pedir chave pública: {e}")

    def initiate_handshake(self, recipient):
        """Inicia o Handshake com Diffie-Hellman"""
        if recipient in self.session_keys and "aes" in self.session_keys[recipient]:
            print(f"[!] Handshake com {recipient} já estabelecido.")
            return
        
        try:
            # Gera o par efêmero DH
            print(f"[DEBUG] Gerando chave DH efêmera...")
            self.dh_private_key, dh_public_bytes = generate_dh_key_pair()
            print(f"[DEBUG] Tamanho da chave DH pública gerada: {len(dh_public_bytes)} bytes")

            # Verifica se temos a chave pública do destinatário
            pubkey_bytes = getattr(self.app, 'contact_public_keys', {}).get(recipient)
            print(f"[DEBUG] Tamanho da chave RSA pública recebida: {len(pubkey_bytes)} bytes")
            if not pubkey_bytes:
                print(f"[!] Chave pública RSA de {recipient} não encontrada.")
                return

            if recipient not in self.session_keys:
                self.session_keys[recipient] = {}

            salt = self.session_keys[recipient].get("salt")
            if not salt:
                salt = os.urandom(16)
                self.session_keys[recipient]["salt"] = salt

            print(f"[DEBUG] Salt utilizado: {salt.hex()}")

            # Junta o salt com a chave DH
            payload = salt + dh_public_bytes
            print(f"[HANDSHAKE] (A - INIT) Salt enviado: {salt.hex()}")
            print(f"[HANDSHAKE] (A - INIT) Minha DH pública (DER): {dh_public_bytes.hex()}")

            print(f"[DEBUG] Tamanho do payload (salt + DH): {len(payload)} bytes")

            # Carrega a chave RSA pública do destinatário
            recipient_rsa_key = serialization.load_pem_public_key(pubkey_bytes)
            print(f"[DEBUG] Chave RSA pública carregada com sucesso, pronta para cifrar.")

            # Criptografa o payload com a RSA do destinatário
            encrypted_payload = recipient_rsa_key.encrypt(
                payload,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"[DEBUG] Payload criptografado com RSA, tamanho: {len(encrypted_payload)} bytes")

            # Envia ao servidor (em base64 para facilitar transporte)
            encoded_payload = base64.b64encode(encrypted_payload).decode('utf-8')
            self.sock.send(f"DHE_INIT:{recipient}:{encoded_payload}".encode('utf-8'))

            print(f"[+] Handshake iniciado com {recipient}. Salt e chave DH enviados.")

        except Exception as e:
            print(f"[!] Erro ao iniciar handshake com {recipient}: {e}")


    def handle_dhe_init(self, sender, encrypted_dh_b64):
        """Recebe o DHE_INIT de outro cliente (usuário A) e responde com sua chave DH."""
        try:
            print(f"[DEBUG] Iniciando handle_dhe_init com {sender}")
            if sender not in self.app.contact_public_keys:
                print(f"[!] Chave pública de {sender} não carregada ainda. Solicitando ao servidor...")
                self.request_public_key(sender)
                return  # Sai do método, vamos tentar de novo quando receber
            
            # Descriptografa o payload recebido (salt + dh_public_bytes)
            encrypted_payload = base64.b64decode(encrypted_dh_b64)
            with open(f"chaves/{self.app.username}_private_key.pem", "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            payload = private_key.decrypt(
                encrypted_payload,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Extrai salt (16 bytes) e a chave DH do peer
            salt = payload[:16]
            peer_dh_bytes = payload[16:]
            print(f"[HANDSHAKE] (B - RECEIVED INIT) Salt recebido: {salt.hex()}")
            print(f"[HANDSHAKE] (B - RECEIVED INIT) DH pública do peer (DER): {peer_dh_bytes.hex()}")

            print(f"[DEBUG] Salt recebido de {sender}: {salt.hex()}")

            # Carrega a chave DH pública do peer (usuário A)
            peer_dh_key = serialization.load_der_public_key(peer_dh_bytes, backend=default_backend())

            # Gera seu próprio par DH (privada e pública)
            self.dh_private_key, my_dh_bytes = generate_dh_key_pair()
            print(f"[HANDSHAKE] (B - RESPONSE) Minha DH pública (DER): {my_dh_bytes.hex()}")

            # Salva a chave pública do outro (para usar depois)
            if not hasattr(self, 'peer_dh_keys'):
                self.peer_dh_keys = {}
                self.peer_dh_keys[sender] = peer_dh_key

            # Criptografa sua própria DH com a RSA de A
            rsa_pubkey_bytes = getattr(self.app, 'contact_public_keys', {}).get(sender)
            if not rsa_pubkey_bytes:
                print(f"[!] Chave pública RSA de {sender} não encontrada.")
                return
            sender_rsa_key = serialization.load_pem_public_key(rsa_pubkey_bytes)
            encrypted_my_dh = sender_rsa_key.encrypt(
                my_dh_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encoded_my_dh = base64.b64encode(encrypted_my_dh).decode('utf-8')
            self.sock.send(f"DHE_RESPONSE:{sender}:{encoded_my_dh}".encode('utf-8'))

            print(f"[+] Enviou DHE_RESPONSE para {sender} com sua chave DH.")

            # Calcula o segredo DH com a chave privada local e a chave pública DH do outro
            shared_key = self.dh_private_key.exchange(peer_dh_key)
            print(f"[HANDSHAKE] Shared Key: {shared_key.hex()}")


            # Aplica o HKDF para derivar 64 bytes (512 bits)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=salt,
                info=None,
                backend=default_backend()
            )
            derived_key = hkdf.derive(shared_key)

            aes_key = derived_key[:32]
            hmac_key = derived_key[32:]
            print(f"\n[DEBUG-HANDSHAKE] Chaves derivadas (handle_dhe_init - RECEBIDO de {sender}):")
            print(f"Shared Key: {shared_key.hex()}")
            print(f"Salt usado: {salt.hex()}")
            print(f"AES Key (32 bytes): {aes_key.hex()}")
            print(f"HMAC Key (32 bytes): {hmac_key.hex()}\n")

            # Armazena/atualiza a sessão com as chaves derivadas
            if not hasattr(self, 'session_keys'):
                self.session_keys = {}

            if sender not in self.session_keys:
                self.session_keys[sender] = {}

            self.session_keys[sender]["salt"] = salt
            self.session_keys[sender]["aes"] = aes_key
            self.session_keys[sender]["hmac"] = hmac_key

        except Exception as e:
            print(f"[!] Erro ao processar DHE_INIT de {sender}: {e}")

    def handle_dhe_response(self, sender, encrypted_dh_b64):

        try:
            if sender not in self.app.contact_public_keys:
                print(f"[!] Chave pública de {sender} não carregada ainda. Solicitando ao servidor...")
                self.request_public_key(sender)
                return 
            print(f"[*] Recebeu DHE_RESPONSE de {sender}")
            encrypted_dh = base64.b64decode(encrypted_dh_b64)

            # Carrega chave RSA privada para descriptografar
            private_key_path = f"chaves/{self.app.username}_private_key.pem"
            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )

            # Descriptografa a chave DH do peer
            peer_dh_bytes = private_key.decrypt(
                encrypted_dh,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )


            # Carrega chave pública DH do outro
            peer_dh_key = serialization.load_der_public_key(peer_dh_bytes, backend=default_backend())

            # Calcula segredo DH usando a chave privada local e a chave pública do outro
            shared_key = self.dh_private_key.exchange(peer_dh_key)
            print(f"[HANDSHAKE] Shared Key: {shared_key.hex()}")


            print(f"[+] Chave DH compartilhada gerada ({len(shared_key)} bytes).")

            # Usa o mesmo salt usado no DHE_INIT
            salt = self.session_keys[sender]["salt"]

            # Deriva AES + HMAC com HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=salt,
                info=None,
                backend=default_backend()
            )
            derived_key = hkdf.derive(shared_key)

            aes_key = derived_key[:32]
            hmac_key = derived_key[32:]

            print(f"\n[DEBUG-HANDSHAKE] Chaves derivadas (handle_dhe_response - RESPOSTA de {sender}):")
            print(f"Shared Key: {shared_key.hex()}")
            print(f"Salt usado: {salt.hex()}")
            print(f"AES Key (32 bytes): {aes_key.hex()}")
            print(f"HMAC Key (32 bytes): {hmac_key.hex()}\n")

            # Garante que a sessão existe
            if sender not in self.session_keys:
                self.session_keys[sender] = {}

            # Salva as chaves derivadas
            self.session_keys[sender]["aes"] = aes_key
            self.session_keys[sender]["hmac"] = hmac_key

            print(f"[✓] Handshake finalizado com {sender}. AES + HMAC prontos para uso.")

        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"[!] Erro ao processar DHE_RESPONSE de {sender}: {e}")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ CLASSE ChatApp - ENGLOBA LÓGICA E DESIGN DA UI ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
class ChatApp(ctk.CTk):
    """Controlador da Interface Gráfica (GUI)"""
    def __init__(self, host='localhost', port=12345):
        super().__init__()
        
        self.host = host
        self.port = port
        self.username = ""
        self.current_chat_partner = None

        self.client_logic = ChatClient(self)
        self.incoming_queue = queue.Queue()

        self.contacts_data = {} # { "user": {"status": "ONLINE", "typing": False, "unread_count": 0} }
        self.chat_histories = {} 
        self.contact_widgets = {}
        self.contact_public_keys = {}

    #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ DESIGN DA UI - Define design da janela, dimensões, temas entre outros ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        self._setup_ui()
        
        self.after(100, self.process_incoming_messages)

    def _setup_ui(self):
        self.title("Chat Privado")
        self.geometry("400x600")
        self.resizable(False, False)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True)

        self._create_login_screen()

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ DESIGN DA UI - Criação da tela de Login ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    def _create_login_screen(self):
        self.login_frame = ctk.CTkFrame(self.main_container)
        self.login_frame.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(self.login_frame, text="Bem-vindo!", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=20, padx=40)
        
        self.username_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Seu nome de usuário", width=200)
        self.username_entry.pack(pady=5, padx=20)
        
        self.server_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Servidor (ex: localhost)", width=200)
        self.server_entry.insert(0, self.host)
        self.server_entry.pack(pady=5, padx=20)

        self.connect_button = ctk.CTkButton(self.login_frame, text="Conectar", command=self.attempt_login)
        self.connect_button.pack(pady=20, padx=20)

        self.login_status_label = ctk.CTkLabel(self.login_frame, text="", text_color="red")
        self.login_status_label.pack(pady=(0, 10))

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ DESING DA UI - Criação da tela principal, contatos e chat ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def _create_main_screen(self):
        self.contacts_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        ctk.CTkLabel(self.contacts_frame, text="Contatos", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=10)
        
        self.contacts_scroll_frame = ctk.CTkScrollableFrame(self.contacts_frame, fg_color="#2B2B2B")
        self.contacts_scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.chat_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        
        chat_header = ctk.CTkFrame(self.chat_frame, fg_color="transparent")
        chat_header.pack(fill="x", padx=10, pady=5)
        
        back_icon = ctk.CTkImage(Image.open("back_arrow.png"), size=(20, 20))
        back_button = ctk.CTkButton(chat_header, text="", image=back_icon, command=self.show_contacts_screen, width=30, height=30)
        back_button.pack(side="left")

        self.chat_partner_label = ctk.CTkLabel(chat_header, text="", font=ctk.CTkFont(size=18, weight="bold"))
        self.chat_partner_label.pack(side="left", padx=10)

        self.chat_textbox = ctk.CTkTextbox(self.chat_frame, state="disabled", fg_color="#2B2B2B")
        self.chat_textbox.pack(fill="both", expand=True, padx=10, pady=5)
        
        message_entry_frame = ctk.CTkFrame(self.chat_frame, fg_color="transparent")
        message_entry_frame.pack(fill="x", padx=10, pady=10)
        
        self.message_entry = ctk.CTkEntry(message_entry_frame, placeholder_text="Digite sua mensagem...")
        self.message_entry.pack(side="left", fill="x", expand=True)
        self.message_entry.bind("<KeyRelease>", self.on_typing)
        self.message_entry.bind("<Return>", self.send_chat_message)
        
        send_button = ctk.CTkButton(message_entry_frame, text="Enviar", width=80, command=self.send_chat_message)
        send_button.pack(side="right", padx=(10, 0))

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ LÓGICA DE CONEXÃO - Coleta os textos dos campos, verifica se tá tudo preenchido, carrega e gera chave, entre outros ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    def attempt_login(self):
        user = self.username_entry.get().strip()
        server = self.server_entry.get().strip()
        if not user or not server:
            self.login_status_label.configure(text="Nome e servidor são obrigatórios.")
            return

        self.username = user
        self.host = server
        self.connect_button.configure(state="disabled", text="Conectando...")
        self.login_status_label.configure(text="")

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ LÓGICA DE CONEXÃO - Gera as chaves privadas e encaminha diretamente pra a pasta local ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        filename = f"chaves/{user}_private_key.pem"

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Caso já existir, essa função vai carregar a chave existente (evita sobreescrever =D) ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if os.path.exists(filename):
            print(f"[+] Chave já existente encontrada para {user}")
            with open(filename, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Caso não existir, criar um novo par de chaves ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            private_key, public_key = generate_rsa_keys()
            try:
                with open(filename, "wb") as f:
                    f.write(private_key)
                print(f"[+] Nova chave privada salva em: {filename}")
            except Exception as e:
                print(f"[!] Erro ao salvar chave privada: {e}")
                self.login_status_label.configure(text="Erro ao salvar chave privada.")
                self.connect_button.configure(state="normal", text="Conectar")
                return
        success = self.client_logic.connect(server, self.port, user, public_key)
        if not success:
            self.connect_button.configure(state="normal", text="Conectar")

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Funções caso o login ocorra corretamente ou falhe ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def on_login_success(self):
        print("[*] Login bem-sucedido.")
        self.login_frame.destroy()
        self._create_main_screen()
        self.show_contacts_screen()
        self.client_logic.request_contact_list()

    def on_login_fail(self, message):
        self.login_status_label.configure(text=message)
        self.connect_button.configure(state="normal", text="Conectar")
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ DESIGN DA UI - Exibir contatos e chat ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def show_contacts_screen(self):
        self.chat_frame.pack_forget()
        self.contacts_frame.pack(fill="both", expand=True)
        self.current_chat_partner = None
        self.title("Contatos")

    def show_chat_screen(self, partner_name):
        if partner_name in self.contacts_data:
            self.contacts_data[partner_name]['unread_count'] = 0
            self.update_unread_badge(partner_name)

        self.current_chat_partner = partner_name
        self.contacts_frame.pack_forget()
        self.chat_frame.pack(fill="both", expand=True)

        self.chat_partner_label.configure(text=partner_name)
        self.title(f"Chat com {partner_name}")

        # ~~~~~~~~~~~~~~~~~~~~~~~~ Solicita automaticamente a chave pública ao abrir o chat ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        self.client_logic.request_public_key(partner_name)

        
        self.chat_textbox.configure(state="normal")
        self.chat_textbox.delete("1.0", "end")
        history = self.chat_histories.get(partner_name, "")
        self.chat_textbox.insert("1.0", history)
        self.chat_textbox.see("end")
        self.chat_textbox.configure(state="disabled")

        if partner_name in self.contacts_data:
            self.update_contact_status(partner_name, self.contacts_data[partner_name]['status'])


    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ LÓGICA - Processamento das mensagens ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    def process_incoming_messages(self):
        while not self.incoming_queue.empty():
            try:
                msg = self.incoming_queue.get_nowait().strip()
                #print("[QUEUE] Mensagem da fila:", repr(msg))
                if not msg:
                    continue
                
                #print("[PROCESSING] Mensagem da fila:", repr(msg))
                if msg.startswith("CHAT:"):
                    _, sender, ts, encrypted_payload = msg.split(":", 3)
                    self.handle_chat_message(sender, ts, encrypted_payload)

                elif msg.startswith("PUBKEY_RESPONSE:"):
                    try:
                        _, target_username, pubkey_b64 = msg.split(":", 2)
                        pubkey_bytes = base64.b64decode(pubkey_b64)
                        print(f"[+] Chave pública de '{target_username}' recebida (total {len(pubkey_bytes)} bytes).")
                        self.store_contact_public_key(target_username, pubkey_bytes)

                        print(f"[*] Iniciando handshake com {target_username} (forçado ao receber chave pública)")
                        self.client_logic.initiate_handshake(target_username)

                    except Exception as e:
                        print(f"[!] Erro ao processar chave pública recebida: {e}")


                elif msg.startswith("PUBKEY_NOTIFY:"):
                    _, content = msg.split(":", 1)
                    print(f"[!] Notificação: {content}")
                elif msg.startswith("TYPING:"):
                    _, who = msg.split(":", 1)
                    self.handle_typing_status(who)
                elif msg.startswith("STATUS:"):
                    _, user, status = msg.split(":", 2)
                    self.handle_status_update(user, status)
                elif msg.startswith("CONTACTS:"):
                    _, user_list_str = msg.split(":", 1)
                    users = user_list_str.split(",") if user_list_str else []
                    self.handle_contacts_update(users)
                elif msg.startswith("DHE_INIT:"):
                    _, sender, dh_b64 = msg.split(":", 2)
                    self.client_logic.handle_dhe_init(sender, dh_b64)
                elif msg.startswith("DHE_RESPONSE:"):
                    try:
                        _, sender, b64 = msg.split(":", 2)
                        b64 = b64.strip()  # muito importante!
                        print(f"[DEBUG] handle_dhe_response acionado com {sender}, base64 tamanho={len(b64)}")
                        self.client_logic.handle_dhe_response(sender, b64)
                    except Exception as e_inner:
                        print(f"[!] Erro ao processar DHE_RESPONSE: {e_inner}") 


                elif msg.startswith("SYSTEM:"):
                    content = msg.split(":", 1)[1]
                    if content == "CONEXAO_PERDIDA":
                        self.handle_disconnection()
                    else:
                        print(f"(!) MENSAGEM DO SISTEMA: {content}")
            except queue.Empty:
                pass
            except Exception as e:
                print(f"[!] Erro ao processar mensagem da fila: '{msg}' -> {e}")
        
        self.after(100, self.process_incoming_messages)
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ LOGICA E DESIGN DA UI ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def handle_chat_message(self, sender, timestamp, text):
        print("[DEBUG] handle_chat_message acionado para:", sender)
        if hasattr(self.client_logic, 'session_keys') and sender in self.client_logic.session_keys:
            session = self.client_logic.session_keys[sender]
            decrypted_text = decifrar_mensagem(text, session["aes"], session["hmac"])

            if decrypted_text is None:
                print(f"[ALERTA] Mensagem de {sender} foi descartada (HMAC inválido!)")
                return  # Não exibe mensagens comprometidas

            text = decrypted_text  # Substitui o texto cifrado pelo texto claro
        else:
            print(f"[!] Sessão segura com {sender} não estabelecida. Ignorando mensagem cifrada.")
            return
        formatted_message = f"[{timestamp}] {sender}: {text}\n"

        if sender not in self.chat_histories:
            self.chat_histories[sender] = ""

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Evita mensagens duplicadas no chat ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        if formatted_message not in self.chat_histories[sender]:
            self.chat_histories[sender] += formatted_message

            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Se o chat estiver aberto com essa pessoa, exibe as mensagens ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            if self.current_chat_partner == sender:
                self.chat_textbox.configure(state="normal")
                self.chat_textbox.insert("end", formatted_message)
                self.chat_textbox.see("end")
                self.chat_textbox.configure(state="disabled")
            else:
                self.contacts_data[sender]['unread_count'] += 1
                self.update_unread_badge(sender)

        self.update_contact_status(sender, self.contacts_data[sender]['status'])

    def handle_typing_status(self, user):
        if user == self.username:
            return

        if user in self.contact_widgets:
            self.update_contact_status(user, "Digitando...")
            self.after(3000, lambda u=user: self.reset_typing_status(u))

    def reset_typing_status(self, user):
        if user in self.contacts_data:
             widget = self.contact_widgets.get(user)
             if widget and widget["frame"].winfo_exists():
                if self.contacts_data[user].get('display_status') == "Digitando...":
                    original_status = self.contacts_data[user]['status']
                    self.update_contact_status(user, original_status)

    def handle_status_update(self, user, status):
        if user == self.username:
            return

        if user not in self.contacts_data:
            self.contacts_data[user] = {"status": "OFFLINE", "typing": False, "unread_count": 0}
        
        self.contacts_data[user]['status'] = status
        self.update_contact_status(user, status)

    def handle_contacts_update(self, user_list):
        for user in user_list:
            if user == self.username:
                continue

            if user not in self.contacts_data:
                self.contacts_data[user] = {"status": "OFFLINE", "typing": False, "unread_count": 0}
                self.create_contact_widget(user)

    def handle_disconnection(self):
        self.main_container.destroy()
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True)
        self._create_login_screen()
        self.login_status_label.configure(text="Conexão com o servidor perdida.")


    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ DESIGN DA UI - Criação de um card novo pra cada contato na lista ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    def create_contact_widget(self, username):
        if username in self.contact_widgets:
            self.contact_widgets[username]["frame"].destroy()

        contact_entry = ctk.CTkFrame(self.contacts_scroll_frame, fg_color="#3A3A3A", corner_radius=10)
        contact_entry.pack(fill="x", padx=5, pady=3)
        contact_entry.bind("<Button-1>", lambda event, u=username: self.show_chat_screen(u))
        
        name_label = ctk.CTkLabel(contact_entry, text=username, anchor="w", font=ctk.CTkFont(size=14))
        name_label.pack(side="left", fill="x", expand=True, padx=10, pady=10)
        name_label.bind("<Button-1>", lambda event, u=username: self.show_chat_screen(u))

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Widget para a notificação ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        unread_badge = ctk.CTkLabel(contact_entry, text="", fg_color="#1F6AA5", corner_radius=8, font=ctk.CTkFont(size=12, weight="bold"))
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ O badge é empacotado mas fica invisível até que seja necessário ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        unread_badge.pack(side="right", padx=5)
        unread_badge.pack_forget() # Esconde o badge inicialmente
        
        status_label = ctk.CTkLabel(contact_entry, text="Offline", anchor="e", width=80)
        status_label.pack(side="right", padx=10)
        status_label.bind("<Button-1>", lambda event, u=username: self.show_chat_screen(u))

        status_indicator = ctk.CTkFrame(contact_entry, width=12, height=12, fg_color="grey", corner_radius=6)
        status_indicator.pack(side="right")
        status_indicator.bind("<Button-1>", lambda event, u=username: self.show_chat_screen(u))

        self.contact_widgets[username] = {
            "frame": contact_entry,
            "name": name_label,
            "status_text": status_label,
            "status_indicator": status_indicator,
            "unread_badge": unread_badge 
        }
        self.update_contact_status(username, self.contacts_data[username]['status'])

    #  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Função para esconder o badge ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def update_unread_badge(self, username):
        if username not in self.contact_widgets:
            return
        
        count = self.contacts_data[username].get('unread_count', 0)
        badge_widget = self.contact_widgets[username]['unread_badge']

        if count > 0:
            badge_widget.configure(text=f" {count} ") # Adiciona espaços para padding
            badge_widget.pack(side="right", padx=(0, 5)) # Mostra o badge
        else:
            badge_widget.pack_forget() # Esconde o badge

    def update_contact_status(self, username, status):
        if username not in self.contact_widgets:
            if username == self.username:
                return
            self.create_contact_widget(username)

        widget_set = self.contact_widgets[username]
        status_text_widget = widget_set["status_text"]
        status_indicator_widget = widget_set["status_indicator"]

        self.contacts_data[username]['display_status'] = status

        if status == "ONLINE":
            status_text_widget.configure(text="Online", text_color="lightgreen")
            status_indicator_widget.configure(fg_color="green")
        elif status == "OFFLINE":
            status_text_widget.configure(text="Offline", text_color="grey")
            status_indicator_widget.configure(fg_color="grey")
        elif status == "Digitando...":
            status_text_widget.configure(text="Digitando...", text_color="cyan")
            status_indicator_widget.configure(fg_color="cyan")


    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~  LÓGICA - Ações do Usuário no chat ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    def on_typing(self, event):
        if self.current_chat_partner:
            self.client_logic.send_typing_notification(self.current_chat_partner)

    def send_chat_message(self, event=None):
        msg_text = self.message_entry.get().strip()
        if not msg_text or not self.current_chat_partner:
            return

        # Verifica se a sessão segura com o contato já está estabelecida
        if self.current_chat_partner not in self.client_logic.session_keys:
            print(f"[!] Sessão com {self.current_chat_partner} ainda não estabelecida. Aguarde handshake.")
            return

        session = self.client_logic.session_keys[self.current_chat_partner]

        # Verifica se as chaves AES e HMAC já foram derivadas (handshake finalizado)
        if "aes" not in session or "hmac" not in session:
            print(f"[!] Handshake com {self.current_chat_partner} ainda não finalizado. Aguarde.")
            return

        # Envia a mensagem cifrada
        self.client_logic.send_message(self.current_chat_partner, msg_text)

        # Exibe a mensagem na interface
        formatted_message = f"[agora] Eu: {msg_text}\n"
        if self.current_chat_partner not in self.chat_histories:
            self.chat_histories[self.current_chat_partner] = ""
        self.chat_histories[self.current_chat_partner] += formatted_message

        self.chat_textbox.configure(state="normal")
        self.chat_textbox.insert("end", formatted_message)
        self.chat_textbox.see("end")
        self.chat_textbox.configure(state="disabled")
        self.message_entry.delete(0, "end")

    def process_pending_messages(self, sender):
        to_process = []
        for msg in self.message_queue:
            if f"CHAT:{sender}:" in msg:
                to_process.append(msg)
        for msg in to_process:
            self.message_queue.remove(msg)
            self.app.process_incoming_message(msg)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Lógica - Função pra armazenar a chave publica dos usuários na memória ~~~~~~~~~~~~~~~~~~~~~~~~
    def store_contact_public_key(self, username, pubkey_bytes):
        if not hasattr(self, 'contact_public_keys'):
            self.contact_public_keys = {}
        self.contact_public_keys[username] = pubkey_bytes
        print(f"[+] Chave pública de '{username}' armazenada na memória. {len(pubkey_bytes)} bytes.")


if __name__ == "__main__":
    try:
        with open("back_arrow.png", "rb") as f:
            pass
    except FileNotFoundError:
        print("\nERRO: Arquivo 'back_arrow.png' não encontrado.")
        print("Por favor, crie ou baixe um ícone de seta para a esquerda e salve-o no mesmo diretório para continuar.\n")
        sys.exit(1)

    app = ChatApp()
    app.mainloop()