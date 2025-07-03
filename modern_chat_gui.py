import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import time

class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Chat Seguro - Cliente")
        self.master.geometry("600x600")
        self.master.resizable(False, False)

        self.username = None
        self.client_socket = None
        self.contatos = []
        self.destinatario_atual = None
        self.typing_timer = None

        self.create_login_screen()

    # ---------- TELA DE LOGIN ---------- #
    def create_login_screen(self):
        self.clear_window()
        ttk.Label(self.master, text="Bem-vindo ao Chat Seguro", font=("Helvetica", 16)).pack(pady=30)
        ttk.Label(self.master, text="Digite seu nome:").pack(pady=10)

        self.name_entry = ttk.Entry(self.master, width=30)
        self.name_entry.pack(pady=5)
        self.name_entry.focus()

        ttk.Button(self.master, text="Entrar", command=self.connect_to_server).pack(pady=20)

    def connect_to_server(self):
        self.username = self.name_entry.get().strip()
        if not self.username:
            messagebox.showwarning("Aviso", "Digite um nome para entrar.")
            return

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect(('localhost', 12345))
            self.client_socket.send(self.username.encode())
            resposta = self.client_socket.recv(1024).decode()
            if resposta != "Nome aceito":
                messagebox.showerror("Erro", resposta)
                return
        except Exception:
            messagebox.showerror("Erro", "Não foi possível conectar ao servidor.")
            return

        self.create_chat_screen()
        threading.Thread(target=self.receive_messages, daemon=True).start()

    # ---------- TELA DO CHAT ---------- #
    def create_chat_screen(self):
        self.clear_window()
        ttk.Label(self.master, text=f"Conectado como: {self.username}", font=("Helvetica", 12)).pack(pady=5)

        # Status do contato
        self.status_label = ttk.Label(self.master, text="Nenhum contato selecionado", foreground="blue")
        self.status_label.pack()

        # Área principal com contatos e chat
        main_frame = ttk.Frame(self.master)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10)

        # Lista de contatos
        self.contacts_list = tk.Listbox(main_frame, width=20, exportselection=False)
        self.contacts_list.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        self.contacts_list.bind("<<ListboxSelect>>", self.select_contact)

        # Janela de conversa
        self.chat_display = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, state='disabled', width=60, height=25)
        self.chat_display.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Entrada de mensagem
        bottom_frame = ttk.Frame(self.master)
        bottom_frame.pack(pady=10)

        self.msg_entry = ttk.Entry(bottom_frame, width=50)
        self.msg_entry.pack(side=tk.LEFT, padx=5)
        self.msg_entry.bind("<Key>", self.send_typing_event)
        self.msg_entry.bind("<Return>", lambda event: self.send_message())

        ttk.Button(bottom_frame, text="Enviar", command=self.send_message).pack(side=tk.LEFT)

    def select_contact(self, event):
        selection = self.contacts_list.curselection()
        if selection:
            index = selection[0]
            self.destinatario_atual = self.contatos[index]
            self.status_label.config(text=f"Conversando com {self.destinatario_atual}")

    def send_typing_event(self, event=None):
        if self.destinatario_atual:
            self.client_socket.send(f"TYPING:{self.destinatario_atual}".encode())

    def send_message(self):
        msg = self.msg_entry.get().strip()
        if msg and self.destinatario_atual:
            try:
                self.client_socket.send(f"MSG:{self.destinatario_atual}:{msg}".encode())
                self.msg_entry.delete(0, tk.END)
            except Exception:
                messagebox.showerror("Erro", "Falha ao enviar mensagem.")
        elif not self.destinatario_atual:
            messagebox.showwarning("Aviso", "Selecione um contato antes de enviar.")

    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(4096).decode('utf-8')
                if not data:
                    break

                if data.startswith("CHAT:"):
                    _, sender, ts, msg = data.split(":", 3)
                    self.append_chat(f"[{ts}] {sender}: {msg}")

                elif data.startswith("TYPING:"):
                    _, who = data.split(":", 1)
                    if who == self.destinatario_atual:
                        self.status_label.config(text=f"{who} está digitando...")
                        if self.typing_timer:
                            self.master.after_cancel(self.typing_timer)
                        self.typing_timer = self.master.after(2000, self.restore_status_label)

                elif data.startswith("STATUS:"):
                    _, nome, st = data.split(":", 2)
                    self.append_chat(f"*** {nome} ficou {st.lower()}")

                elif data.startswith("CONTACTS:"):
                    _, lista = data.split(":", 1)
                    self.contatos = lista.split(",") if lista else []
                    self.update_contacts()

                elif data.startswith("SYSTEM:"):
                    self.append_chat(f"[!] {data.replace('SYSTEM:', '')}")

            except Exception as e:
                self.append_chat(f"[ERRO] Conexão perdida: {e}")
                break

    def append_chat(self, texto):
        self.chat_display.configure(state='normal')
        self.chat_display.insert(tk.END, texto + "\n")
        self.chat_display.configure(state='disabled')
        self.chat_display.see(tk.END)

    def update_contacts(self):
        self.contacts_list.delete(0, tk.END)
        for nome in self.contatos:
            if nome != self.username:
                self.contacts_list.insert(tk.END, nome)

    def restore_status_label(self):
        if self.destinatario_atual:
            self.status_label.config(text=f"Conversando com {self.destinatario_atual}")
        else:
            self.status_label.config(text="Nenhum contato selecionado")

    def clear_window(self):
        for widget in self.master.winfo_children():
            widget.destroy()

# ---------- Execução principal ---------- #
if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style(root)
    style.theme_use('clam')
    ChatClient(root)
    root.mainloop()
