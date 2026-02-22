import os
import json
import threading
import socket
import tkinter as tk
from tkinter import ttk, messagebox
from common import (
    generate_client_x25519,
    b64e, b64d,
    send_json, recv_json,
    verify_cert, extract_subject_pubkey_raw,
    x25519_shared_secret,
    derive_master_key_km, derive_session_key_ks,
    aes_encrypt, aes_decrypt
)

CA_PORT = 9000
CLIENT1_LISTEN_PORT = 9101

class Client1Gui:
    def __init__(self, root):
        self.root = root
        self.root.title("BIM437 - Client 1 (Initiator)")
        self.my_x25519_priv = None
        self.my_x25519_pub_raw = None
        self.my_cert = None
        self.peer_cert = None
        self.km = None
        self.ks = None
        self.nonce1 = None
        self.nonce2 = None
        self.conn = None
        self.chat_thread = None
        self.stop_chat = threading.Event()
        self.connection_active = False
        self.server_socket = None
        
        frm = ttk.Frame(root, padding=12)
        frm.pack(fill="both", expand=True)
        
        ttk.Label(frm, text="CA IP:").grid(row=0, column=0, sticky="w")
        self.ca_ip = tk.StringVar(value="127.0.0.1")
        ttk.Entry(frm, textvariable=self.ca_ip, width=20).grid(row=0, column=1, sticky="w")
        
        ttk.Label(frm, text="Client2 IP:").grid(row=0, column=2, sticky="w")
        self.client2_ip = tk.StringVar(value="127.0.0.1")
        ttk.Entry(frm, textvariable=self.client2_ip, width=20).grid(row=0, column=3, sticky="w")
        
        ttk.Button(frm, text="1) Generate My Key", command=self.gen_key).grid(row=1, column=0, sticky="ew", pady=6)
        ttk.Button(frm, text="2) Request Certificate", command=self.req_cert).grid(row=1, column=1, sticky="ew", pady=6)
        ttk.Label(frm, text=f"Listening port {CLIENT1_LISTEN_PORT}").grid(row=2, column=0, sticky="w")
        ttk.Button(frm, text="3) Start Server", command=self.start_server).grid(row=2, column=1, sticky="ew", pady=6)
        
        ttk.Separator(frm, orient='horizontal').grid(row=3, column=0, columnspan=4, sticky="ew", pady=10)
        
        ttk.Label(frm, text="Chat (after key exchange):").grid(row=4, column=0, columnspan=2, sticky="w")
        
        self.chat_log = tk.Text(frm, height=6, width=80)
        self.chat_log.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=5)
        
        ttk.Label(frm, text="Message:").grid(row=6, column=0, sticky="w")
        self.message_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.message_var, width=60).grid(row=6, column=1, columnspan=2, sticky="ew", pady=5)
        ttk.Button(frm, text="Send", command=self.send_chat_message).grid(row=6, column=3, sticky="ew", pady=5)
        
        self.log = tk.Text(frm, height=12, width=100)
        self.log.grid(row=7, column=0, columnspan=4, sticky="nsew", pady=8)
        
        for c in range(4):
            frm.columnconfigure(c, weight=1)
        frm.rowconfigure(5, weight=1)
        frm.rowconfigure(7, weight=1)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def write(self, s):
        self.root.after(0, lambda: self._write(s))
    
    def _write(self, s):
        self.log.insert("end", s + "\n")
        self.log.see("end")
    
    def write_chat(self, s):
        self.root.after(0, lambda: self._write_chat(s))
    
    def _write_chat(self, s):
        self.chat_log.insert("end", s + "\n")
        self.chat_log.see("end")

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
                    "subject_id": "Client1",
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

    def start_server(self):
        if not self.my_cert:
            messagebox.showerror("Error", "Request certificate first.")
            return
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        threading.Thread(target=self.server_loop, daemon=True).start()
        self.write(f"Waiting Client2 on 0.0.0.0:{CLIENT1_LISTEN_PORT} ...")

    def server_loop(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", CLIENT1_LISTEN_PORT))
            self.server_socket.listen(1)
            self.server_socket.settimeout(1)
            
            self.write("Server ready. Waiting for connection...")
            
            while not self.stop_chat.is_set():
                try:
                    conn, addr = self.server_socket.accept()
                    break
                except socket.timeout:
                    continue
                except OSError:
                    break
            
            if self.stop_chat.is_set():
                return
                
            self.conn = conn
            self.connection_active = True
            self.write(f"Connected: Client2 from {addr}")
            
            try:
                send_json(self.conn, {"type": "CERT", "certificate": self.my_cert})
                msg = recv_json(self.conn)
                if msg.get("type") != "CERT":
                    self.write("ERROR: Unexpected message.")
                    self.connection_active = False
                    return
                
                self.peer_cert = msg["certificate"]
                ok = verify_cert(self.peer_cert)
                self.write(f"Client2 certificate verify: {ok}")
                if not ok:
                    self.write("Invalid peer certificate. Abort.")
                    self.connection_active = False
                    return
                
                self.write("Certificate exchange complete.")
                self.exchange_master_key()
                
            except Exception as e:
                self.write(f"Error in server loop: {e}")
                self.connection_active = False
                
        except Exception as e:
            self.write(f"Server error: {e}")
        finally:
            if self.server_socket:
                try:
                    self.server_socket.close()
                except:
                    pass

    def exchange_master_key(self):
        try:
            self.nonce1 = os.urandom(16)
            
            msg1 = {
                "type": "MSG1",
                "nonce1": b64e(self.nonce1),
                "id": "Client1"
            }
            send_json(self.conn, msg1)
            self.write("Sent MSG1: [N1 || ID_A]")
            
            msg2_data = recv_json(self.conn)
            if msg2_data.get("type") != "MSG2":
                self.write("ERROR: Expected MSG2")
                self.connection_active = False
                return
            
            received_nonce1 = b64d(msg2_data["nonce1"])
            self.nonce2 = b64d(msg2_data["nonce2"])
            
            if received_nonce1 != self.nonce1:
                self.write("ERROR: Nonce mismatch")
                self.connection_active = False
                return
            
            self.write("Received MSG2: [N1 || N2]")
            
            msg3 = {
                "type": "MSG3",
                "nonce2": b64e(self.nonce2)
            }
            send_json(self.conn, msg3)
            self.write("Sent MSG3: N2")
            
            msg4_data = recv_json(self.conn)
            if msg4_data.get("type") != "MSG4":
                self.write("ERROR: Expected MSG4")
                self.connection_active = False
                return
            
            ky = b64d(msg4_data["ky"])
            
            peer_x25519_pub_raw = extract_subject_pubkey_raw(self.peer_cert)
            shared = x25519_shared_secret(self.my_x25519_priv, peer_x25519_pub_raw)
            
            context = self.nonce1 + self.nonce2
            self.km = derive_master_key_km(shared, context)
            self.ks = derive_session_key_ks(self.km, context)
            
            self.write("Master key exchange complete.")
            self.write(f"Shared secret (hex): {shared.hex()}")
            self.write(f"Km (hex): {self.km.hex()}")
            self.write(f"Ks (hex): {self.ks.hex()}")
            self.write("Key derivation successful!")
            
            self.write_chat("=== Secure Chat Started ===")
            self.write_chat("Keys established. You can now send encrypted messages.")
            
            self.stop_chat.clear()
            self.chat_thread = threading.Thread(target=self.chat_listener, daemon=True)
            self.chat_thread.start()
            
        except Exception as e:
            self.write(f"Exchange error: {e}")
            self.connection_active = False

    def chat_listener(self):
        while self.connection_active and not self.stop_chat.is_set():
            try:
                msg = recv_json(self.conn)
                if msg and msg.get("type") == "CHAT":
                    encrypted_msg = msg["data"]
                    decrypted = aes_decrypt(self.ks, encrypted_msg)
                    self.write_chat(f"Client2: {decrypted}")
            except (ConnectionError, OSError, json.JSONDecodeError) as e:
                if self.connection_active:
                    self.write(f"Chat listener stopped: {e}")
                break
            except Exception as e:
                if self.connection_active:
                    self.write(f"Chat listener error: {e}")
                continue

    def send_chat_message(self):
        if not self.ks:
            messagebox.showerror("Error", "Establish secure connection first.")
            return
        if not self.connection_active or self.conn is None:
            messagebox.showerror("Error", "Connection lost. Restart the server.")
            return
        
        message = self.message_var.get().strip()
        if not message:
            return
        
        try:
            encrypted = aes_encrypt(self.ks, message)
            send_json(self.conn, {"type": "CHAT", "data": encrypted})
            self.write_chat(f"You: {message}")
            self.message_var.set("")
        except (ConnectionError, OSError) as e:
            self.write(f"Send error - connection lost: {e}")
            self.connection_active = False
        except Exception as e:
            self.write(f"Send error: {e}")

    def on_closing(self):
        self.stop_chat.set()
        self.connection_active = False
        if self.conn:
            try:
                self.conn.close()
            except:
                pass
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        self.root.destroy()

def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    Client1Gui(root)
    root.mainloop()

if __name__ == "__main__":
    main()