import socket
import threading
from database import salvar_mensagem

HOST = 'localhost'
PORT = 12345

clients = []
usernames = {}

def broadcast(message, sender_conn=None):
    for client in clients:
        try:
            if client != sender_conn:  # evita duplicar para quem enviou
                client.send(message.encode())
        except:
            client.close()
            clients.remove(client)

def handle_client(conn, addr):
    print(f"[+] Conectado por {addr}")
    try:
        username = conn.recv(1024).decode()
        usernames[conn] = username
        welcome = f"{username} entrou no chat."
        print(welcome)
        broadcast(welcome, conn)

        while True:
            msg = conn.recv(1024).decode()
            if not msg:
                break
            mensagem_completa = f"{username}: {msg}"
            salvar_mensagem(username, msg)
            broadcast(mensagem_completa, conn)
    except:
        pass
    finally:
        print(f"[-] {addr} desconectado.")
        if conn in clients:
            clients.remove(conn)
        broadcast(f"{usernames.get(conn, 'Um usuário')} saiu do chat.", conn)
        conn.close()

def main():
    from database import init_db
    init_db()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"Servidor ouvindo em {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        clients.append(conn)
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    main()
