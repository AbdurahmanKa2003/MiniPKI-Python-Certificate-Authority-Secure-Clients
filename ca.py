import threading
import socket
import tkinter as tk
from tkinter import ttk, messagebox

from common import (
    generate_ca_rsa, ca_public_pem,
    build_cert_unsigned, sign_cert,
    b64e, recv_json, send_json,
    now_utc_iso, iso_plus_days
)

CA_HOST = "0.0.0.0"
CA_PORT = 9000

class CAGui:
    def __init__(self, root):
        self.root = root
        self.root.title("BIM437 - Certificate Authority (CA)")
        self.ca_priv = None
        self.serial = 1000
        self.server_thread = None
        self.stop_flag = threading.Event()
        frm = ttk.Frame(root, padding=12)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="CA Server").grid(row=0, column=0, sticky="w")
        self.status = tk.StringVar(value="Status: OFF")
        ttk.Label(frm, textvariable=self.status).grid(row=0, column=1, sticky="w")
        ttk.Button(frm, text="Generate CA RSA Keys", command=self.gen_ca).grid(row=1, column=0, sticky="ew", pady=6)
        ttk.Button(frm, text="Start CA Server (port 9000)", command=self.start_server).grid(row=1, column=1, sticky="ew", pady=6)
        self.log = tk.Text(frm, height=18, width=90)
        self.log.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=8)
        frm.columnconfigure(0, weight=1)
        frm.columnconfigure(1, weight=1)
        frm.rowconfigure(2, weight=1)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def write(self, s):
        self.log.insert("end", s + "\n")
        self.log.see("end")

    def gen_ca(self):
        self.ca_priv = generate_ca_rsa()
        pub_pem = ca_public_pem(self.ca_priv).decode("utf-8").strip()
        self.write("CA RSA keys generated.")
        self.write("CA Public Key (PEM):")
        self.write(pub_pem)

    def start_server(self):
        if self.ca_priv is None:
            messagebox.showerror("Error", "Generate CA keys first.")
            return
        if self.server_thread and self.server_thread.is_alive():
            messagebox.showinfo("Info", "Server is already running.")
            return
        self.stop_flag.clear()
        self.server_thread = threading.Thread(target=self.server_loop, daemon=True)
        self.server_thread.start()
        self.status.set(f"Status: ON (listening {CA_HOST}:{CA_PORT})")
        self.write(f"CA listening on {CA_HOST}:{CA_PORT}")

    def server_loop(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((CA_HOST, CA_PORT))
            s.listen(5)
            s.settimeout(1.0)
            while not self.stop_flag.is_set():
                try:
                    conn, addr = s.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

    def handle_client(self, conn, addr):
        with conn:
            try:
                req = recv_json(conn)
                subject_id = req["subject_id"]
                algo = req["public_key_algo"]
                pub_b64 = req["public_key_value_b64"]
                self.serial += 1
                cert_unsigned = build_cert_unsigned(
                    subject_id=subject_id,
                    subject_pub_algo=algo,
                    subject_pub_b64=pub_b64,
                    serial=self.serial,
                    not_before=now_utc_iso(),
                    not_after=iso_plus_days(365),
                    issuer_id="BIM437-CA",
                    ca_pub_pem_b64=b64e(ca_public_pem(self.ca_priv))
                )
                cert = sign_cert(self.ca_priv, cert_unsigned)
                send_json(conn, {"ok": True, "certificate": cert})
                self.write(f"Certificate for {subject_id} to {addr}, serial={self.serial}")
            except Exception as e:
                try:
                    send_json(conn, {"ok": False, "error": str(e)})
                except Exception:
                    pass
                self.write(f"ERROR {addr}: {e}")

    def on_close(self):
        self.stop_flag.set()
        self.root.destroy()

def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    CAGui(root)
    root.mainloop()

if __name__ == "__main__":
    main()