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
import os
import base64


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ GUI_CLIENT.PY ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Essa parte do código é responsável pelo design da interface gráfica e também da lógica.


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

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ LÓGICA: A classe ChatClient é responsável pela lógica da conexão da rede ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
class ChatClient:
    """Lógica de Rede do Cliente (Refatorada)"""
    def __init__(self, app_controller):
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.app = app_controller
        self.buffer = ""
        self.COMMAND_PREFIXES = ["CHAT:", "TYPING:", "STATUS:", "CONTACTS:", "SYSTEM:", "PUBKEY_RESPONSE:", "PUBKEY_NOTIFY:"]

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
            self.sock.send(f"MSG:{recipient}:{message}".encode('utf-8'))
        except Exception as e:
            print(f"[!] Erro ao enviar mensagem: {e}")

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
            start_search_pos = 1 
            
            for prefix in self.COMMAND_PREFIXES:
                pos = self.buffer.find(prefix, start_search_pos)
                if pos != -1 and (next_msg_start == -1 or pos < next_msg_start):
                    next_msg_start = pos
            
            if next_msg_start != -1:
                message = self.buffer[:next_msg_start]
                self.buffer = self.buffer[next_msg_start:]
                self.app.incoming_queue.put(message)
                continue
            else:
                message = self.buffer
                self.buffer = ""
                self.app.incoming_queue.put(message)
                break

    def _receive_loop(self):
        while True:
            try:
                data = self.sock.recv(4096).decode('utf-8')
                if not data:
                    raise ConnectionResetError()
                
                self.buffer += data
                self._process_buffer()

            except Exception as e:
                print(f"\n[!] Conexão perdida: {e}")
                self.app.incoming_queue.put(f"SYSTEM:CONEXAO_PERDIDA")
                self.sock.close()
                break

    def request_public_key(self, username):
        try:
            print(f"\n[*] Cliente está pedindo ao servidor a chave pública de '{username}'...")
            self.sock.send(f"PUBKEY_REQUEST:{username}".encode('utf-8'))
        except Exception as e:
            print(f"[!] Erro ao pedir chave pública: {e}")

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
                msg = self.incoming_queue.get_nowait()
                
                if msg.startswith("CHAT:"):
                    _, sender, ts, txt = msg.split(":", 3)
                    self.handle_chat_message(sender, ts, txt)
                elif msg.startswith("PUBKEY_RESPONSE:"):
                    try:
                        # print(f"[DEBUG] Mensagem recebida (PUBKEY_RESPONSE): {msg}") ~~~~~~~~~~~ Com esse print podemos ver a chave publica da pessoa em questão no terminal
                        _, target_username, pubkey_b64 = msg.split(":", 2)
                        pubkey_bytes = base64.b64decode(pubkey_b64)
                        print(f"[+] Recebeu do servidor a chave pública de '{target_username}' (total {len(pubkey_bytes)} bytes).")
                        self.store_contact_public_key(target_username, pubkey_bytes)
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

        self.client_logic.send_message(self.current_chat_partner, msg_text)
        
        formatted_message = f"[agora] Eu: {msg_text}\n"
        
        if self.current_chat_partner not in self.chat_histories:
            self.chat_histories[self.current_chat_partner] = ""
        self.chat_histories[self.current_chat_partner] += formatted_message
        
        self.chat_textbox.configure(state="normal")
        self.chat_textbox.insert("end", formatted_message)
        self.chat_textbox.see("end")
        self.chat_textbox.configure(state="disabled")
        
        self.message_entry.delete(0, "end")

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