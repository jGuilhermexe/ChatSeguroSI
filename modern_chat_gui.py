import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading

class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Chat Seguro - Cliente")
        self.master.geometry("500x600")
        self.master.resizable(False, False)
        self.username = None
        self.client_socket = None

        self.create_login_screen()

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
        except:
            messagebox.showerror("Erro", "Não foi possível conectar ao servidor.")
            return

        self.create_chat_screen()
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def create_chat_screen(self):
        self.clear_window()

        ttk.Label(self.master, text=f"Conectado como: {self.username}", font=("Helvetica", 12)).pack(pady=10)

        self.chat_display = scrolledtext.ScrolledText(self.master, wrap=tk.WORD, state='disabled', width=60, height=25)
        self.chat_display.pack(padx=10, pady=10)

        frame = ttk.Frame(self.master)
        frame.pack(pady=10)

        self.msg_entry = ttk.Entry(frame, width=40)
        self.msg_entry.pack(side=tk.LEFT, padx=5)
        self.msg_entry.bind("<Return>", lambda event: self.send_message())

        ttk.Button(frame, text="Enviar", command=self.send_message).pack(side=tk.LEFT)

    def send_message(self):
        msg = self.msg_entry.get().strip()
        if msg:
            try:
                self.client_socket.send(msg.encode())
                self.msg_entry.delete(0, tk.END)
            except:
                messagebox.showerror("Erro", "Falha ao enviar mensagem.")

    def receive_messages(self):
        while True:
            try:
                msg = self.client_socket.recv(1024).decode()
                if msg:
                    self.chat_display.configure(state='normal')
                    self.chat_display.insert(tk.END, msg + "\n")
                    self.chat_display.configure(state='disabled')
                    self.chat_display.see(tk.END)
            except:
                break

    def clear_window(self):
        for widget in self.master.winfo_children():
            widget.destroy()

# Execução principal
if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style(root)
    style.theme_use('clam')
    ChatClient(root)
    root.mainloop()
