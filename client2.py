import os
import json
import threading
import socket
import tkinter as tk
from tkinter import ttk, messagebox
import logging

from common import (
    generate_client_x25519,
    b64e, b64d,
    send_json, recv_json,
    verify_cert, extract_subject_pubkey_raw,
    x25519_shared_secret,
    derive_master_key_km, derive_session_key_ks,
    aes_encrypt, aes_decrypt
)

# Настройка логирования
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Client2")

CA_PORT = 9000
CLIENT1_PORT = 9101

class Client2Gui:
    def __init__(self, root):
        self.root = root
        self.root.title("BIM437 - Client 2 (Responder)")
        self.my_x25519_priv = None
        self.my_x25519_pub_raw = None
        self.my_cert = None
        self.peer_cert = None
        self.km = None
        self.ks = None
        self.nonce1 = None
        self.nonce2 = None
        self.sock = None
        self.chat_thread = None
        self.stop_chat = threading.Event()
        self.connection_active = False
        
        frm = ttk.Frame(root, padding=12)
        frm.pack(fill="both", expand=True)
        
        ttk.Label(frm, text="CA IP:").grid(row=0, column=0, sticky="w")
        self.ca_ip = tk.StringVar(value="127.0.0.1")
        ttk.Entry(frm, textvariable=self.ca_ip, width=20).grid(row=0, column=1, sticky="w")
        
        ttk.Label(frm, text="Client1 IP:").grid(row=0, column=2, sticky="w")
        self.client1_ip = tk.StringVar(value="127.0.0.1")
        ttk.Entry(frm, textvariable=self.client1_ip, width=20).grid(row=0, column=3, sticky="w")
        
        ttk.Button(frm, text="1) Generate My Key", command=self.gen_key).grid(row=1, column=0, sticky="ew", pady=6)
        ttk.Button(frm, text="2) Request Certificate", command=self.req_cert).grid(row=1, column=1, sticky="ew", pady=6)
        ttk.Button(frm, text="3) Connect to Client1", command=self.connect_client1).grid(row=1, column=2, columnspan=2, sticky="ew", pady=6)
        
        ttk.Separator(frm, orient='horizontal').grid(row=2, column=0, columnspan=4, sticky="ew", pady=10)
        
        ttk.Label(frm, text="Chat (after key exchange):").grid(row=3, column=0, columnspan=2, sticky="w")
        
        self.chat_log = tk.Text(frm, height=6, width=80)
        self.chat_log.grid(row=4, column=0, columnspan=3, sticky="nsew", pady=5)
        
        ttk.Label(frm, text="Message:").grid(row=5, column=0, sticky="w")
        self.message_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.message_var, width=60).grid(row=5, column=1, columnspan=2, sticky="ew", pady=5)
        ttk.Button(frm, text="Send", command=self.send_chat_message).grid(row=5, column=3, sticky="ew", pady=5)
        
        self.log = tk.Text(frm, height=12, width=100)
        self.log.grid(row=6, column=0, columnspan=4, sticky="nsew", pady=8)
        
        for c in range(4):
            frm.columnconfigure(c, weight=1)
        frm.rowconfigure(4, weight=1)
        frm.rowconfigure(6, weight=1)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        logger.info("Client2 GUI initialized")

    def write(self, s):
        self.root.after(0, lambda: self._write(s))
    
    def _write(self, s):
        self.log.insert("end", s + "\n")
        self.log.see("end")
        logger.info(s)
    
    def write_chat(self, s):
        self.root.after(0, lambda: self._write_chat(s))
    
    def _write_chat(self, s):
        self.chat_log.insert("end", s + "\n")
        self.chat_log.see("end")
        logger.info(f"Chat: {s}")

    def gen_key(self):
        self.my_x25519_priv, self.my_x25519_pub_raw = generate_client_x25519()
        self.write("Generated X25519 keypair.")
        self.write(f"X25519 public key: {b64e(self.my_x25519_pub_raw)}")

    def req_cert(self):
        if not self.my_x25519_pub_raw:
            messagebox.showerror("Error", "Generate your key first.")
            return
        ca_ip = self.ca_ip.get().strip()
        try:
            with socket.create_connection((ca_ip, CA_PORT), timeout=5) as s:
                req = {
                    "subject_id": "Client2",
                    "public_key_algo": "X25519",
                    "public_key_value_b64": b64e(self.my_x25519_pub_raw),
                }
                send_json(s, req)
                resp = recv_json(s)
            if not resp.get("ok"):
                raise RuntimeError(resp.get("error", "Unknown CA error"))
            self.my_cert = resp["certificate"]
            ok = verify_cert(self.my_cert)
            self.write("Certificate received from CA.")
            self.write(f"Certificate verify: {ok}")
            if not ok:
                messagebox.showerror("Error", "CA certificate verification failed!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def connect_client1(self):
        if not self.my_cert:
            messagebox.showerror("Error", "Request certificate first.")
            return
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        threading.Thread(target=self.client_thread, daemon=True).start()

    def client_thread(self):
        ip = self.client1_ip.get().strip()
        try:
            logger.info(f"Connecting to {ip}:{CLIENT1_PORT}")
            self.sock = socket.create_connection((ip, CLIENT1_PORT), timeout=10)
            self.sock.settimeout(30.0)  # Большой таймаут для отладки
            self.connection_active = True
            logger.info("Connected successfully")
            
            msg = recv_json(self.sock)
            logger.info(f"Received certificate message: {msg.get('type')}")
            if msg.get("type") != "CERT":
                self.write("ERROR: Unexpected message.")
                self.connection_active = False
                return
            
            self.peer_cert = msg["certificate"]
            ok = verify_cert(self.peer_cert)
            self.write(f"Client1 certificate verify: {ok}")
            if not ok:
                self.write("Invalid peer certificate. Abort.")
                self.connection_active = False
                return
            
            send_json(self.sock, {"type": "CERT", "certificate": self.my_cert})
            self.write("Certificate exchange complete.")
            self.exchange_master_key()
            
        except Exception as e:
            logger.error(f"Connection error: {e}")
            self.write(f"Connection error: {e}")
            self.connection_active = False

    def exchange_master_key(self):
        try:
            logger.info("Starting key exchange...")
            msg1_data = recv_json(self.sock)
            logger.info(f"Received MSG1: {msg1_data.get('type')}")
            if msg1_data.get("type") != "MSG1":
                self.write("ERROR: Expected MSG1")
                self.connection_active = False
                return
            
            self.nonce1 = b64d(msg1_data["nonce1"])
            peer_id = msg1_data["id"]
            
            self.write(f"Received MSG1: N1={self.nonce1.hex()}, ID={peer_id}")
            
            self.nonce2 = os.urandom(16)
            
            msg2 = {
                "type": "MSG2",
                "nonce1": b64e(self.nonce1),
                "nonce2": b64e(self.nonce2)
            }
            send_json(self.sock, msg2)
            self.write("Sent MSG2: [N1 || N2]")
            logger.info("Sent MSG2")
            
            msg3_data = recv_json(self.sock)
            logger.info(f"Received MSG3: {msg3_data.get('type')}")
            if msg3_data.get("type") != "MSG3":
                self.write("ERROR: Expected MSG3")
                self.connection_active = False
                return
            
            received_nonce2 = b64d(msg3_data["nonce2"])
            
            if received_nonce2 != self.nonce2:
                self.write("ERROR: Nonce2 mismatch")
                self.connection_active = False
                return
            
            self.write("Received MSG3: N2 verified")
            
            peer_x25519_pub_raw = extract_subject_pubkey_raw(self.peer_cert)
            shared = x25519_shared_secret(self.my_x25519_priv, peer_x25519_pub_raw)
            
            context = self.nonce1 + self.nonce2
            self.km = derive_master_key_km(shared, context)
            self.ks = derive_session_key_ks(self.km, context)
            
            ky = os.urandom(32)
            
            msg4 = {
                "type": "MSG4",
                "ky": b64e(ky)
            }
            send_json(self.sock, msg4)
            self.write("Sent MSG4: K_y")
            logger.info("Sent MSG4")
            
            self.write("Master key exchange complete.")
            self.write(f"Shared secret (hex): {shared.hex()}")
            self.write(f"Km (hex): {self.km.hex()}")
            self.write(f"Ks (hex): {self.ks.hex()}")
            self.write("Key derivation successful! Keys match Client1.")
            
            self.write_chat("=== Secure Chat Started ===")
            self.write_chat("Keys established. You can now send encrypted messages.")
            
            self.stop_chat.clear()
            self.chat_thread = threading.Thread(target=self.chat_listener, daemon=True)
            self.chat_thread.start()
            logger.info("Chat listener started")
            
        except Exception as e:
            logger.error(f"Exchange error: {e}")
            self.write(f"Exchange error: {e}")
            self.connection_active = False

    def chat_listener(self):
        logger.info("Chat listener thread started")
        while self.connection_active and not self.stop_chat.is_set():
            try:
                logger.debug("Waiting for chat message...")
                msg = recv_json(self.sock)
                logger.info(f"Received message type: {msg.get('type') if msg else 'None'}")
                
                if msg and msg.get("type") == "CHAT":
                    encrypted_msg = msg["data"]
                    logger.debug(f"Encrypted message received, length: {len(encrypted_msg)}")
                    decrypted = aes_decrypt(self.ks, encrypted_msg)
                    logger.info(f"Decrypted message: {decrypted}")
                    self.write_chat(f"Client1: {decrypted}")
                elif msg:
                    logger.warning(f"Unexpected message type: {msg.get('type')}")
                    
            except socket.timeout:
                logger.debug("Socket timeout, continuing...")
                continue
            except (ConnectionError, OSError, json.JSONDecodeError) as e:
                logger.error(f"Chat listener error: {e}")
                if self.connection_active:
                    self.write(f"Chat listener stopped: {e}")
                break
            except Exception as e:
                logger.error(f"Unexpected error in chat listener: {e}")
                if self.connection_active:
                    self.write(f"Chat listener error: {e}")
                continue
        logger.info("Chat listener thread ended")

    def send_chat_message(self):
        if not self.ks:
            messagebox.showerror("Error", "Establish secure connection first.")
            return
        if not self.connection_active or self.sock is None:
            messagebox.showerror("Error", "Connection lost. Reconnect to Client1.")
            return
        
        message = self.message_var.get().strip()
        if not message:
            return
        
        try:
            logger.info(f"Sending message: {message}")
            encrypted = aes_encrypt(self.ks, message)
            send_json(self.sock, {"type": "CHAT", "data": encrypted})
            self.write_chat(f"You: {message}")
            self.message_var.set("")
            logger.info("Message sent successfully")
        except (ConnectionError, OSError) as e:
            logger.error(f"Send error - connection lost: {e}")
            self.write(f"Send error - connection lost: {e}")
            self.connection_active = False
        except Exception as e:
            logger.error(f"Send error: {e}")
            self.write(f"Send error: {e}")

    def on_closing(self):
        logger.info("Closing Client2...")
        self.stop_chat.set()
        self.connection_active = False
        if self.sock:
            try:
                self.sock.close()
                logger.info("Socket closed")
            except Exception as e:
                logger.error(f"Error closing socket: {e}")
        self.root.destroy()
        logger.info("Client2 GUI destroyed")

def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    Client2Gui(root)
    root.mainloop()

if __name__ == "__main__":
    main()