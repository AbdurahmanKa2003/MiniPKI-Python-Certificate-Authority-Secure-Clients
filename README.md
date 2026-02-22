 # 🔐 MiniPKI — Python Certificate Authority & Secure Clients

MiniPKI is an educational project that implements a simplified Public Key Infrastructure (PKI) system using Python.

The project demonstrates how a Certificate Authority (CA) issues digital certificates and how clients use them for secure communication.

This project is designed for learning purposes in computer and network security.

---

## 📁 Project Structure

```
MiniPKI/
│
├── ca.py          # Certificate Authority server
├── client1.py     # Client 1
├── client2.py     # Client 2
├── common.py      # Shared cryptographic utilities
├── requirements.txt
└── README.md
```

---

## 🚀 Features

### ✅ Certificate Authority (CA)
- Generates RSA key pair
- Signs client certificates
- Manages certificate serial numbers
- Runs as a TCP server
- Provides GUI interface using Tkinter

### ✅ Clients
- Generate X25519 key pairs
- Send certificate requests
- Receive signed certificates
- Establish secure connections

### ✅ Cryptography
- RSA (for CA signing)
- X25519 (for key exchange)
- SHA-256 hashing
- Base64 encoding
- Digital signatures

---

## 🧩 Technologies Used

- Python 3.9+
- cryptography library
- Socket programming
- Tkinter (GUI)
- JSON
- Threading

---


## ▶️ How to Run

### 1. Start the Certificate Authority

```bash
python ca.py
```

A GUI window will appear.

1. Click **Generate CA RSA Keys**
2. Click **Start CA Server**

The CA will listen on port `9000`.

---

### 2. Run the Clients

Open two separate terminals.

#### Client 1
```bash
python client1.py
```

#### Client 2
```bash
python client2.py
```

Both clients will connect to the CA and request certificates.

---

## 🔄 System Workflow

```
Client → Certificate Request → CA
Client ← Signed Certificate ← CA
```

1. Client generates key pair
2. Client sends public key to CA
3. CA signs certificate
4. Client receives certificate
5. Secure channel is established

---

## 📜 Certificate Format

Each certificate contains:

- Subject ID
- Public Key
- Serial Number
- Validity Period
- Issuer Information
- CA Digital Signature

All data is transmitted in JSON format.

---

## 🔐 Security Concepts

This project implements:

✔ Asymmetric cryptography  
✔ Digital signatures  
✔ Public Key Infrastructure (PKI)  
✔ Certificate validation  
✔ Data integrity verification  

This system follows a simplified TLS-like model.

---

## 🎓 Educational Purpose

This project demonstrates:

- How PKI systems work
- Certificate Authority trust model
- Digital certificate issuance
- Secure client communication
- Cryptographic protocol design

It is intended for cybersecurity students and beginners.

---

## ⚠️ Limitations

- Not suitable for production use
- No certificate revocation (CRL/OCSP)
- No full TLS implementation
- No advanced authentication
- Minimal error handling

---

## 📈 Future Improvements

- Add certificate revocation list (CRL)
- Implement OCSP
- Support TLS/SSL
- Improve logging system
- Add user authentication
- Add encrypted storage




---

## 📄 License

MIT License

This project is open-source and intended for educational use only.
