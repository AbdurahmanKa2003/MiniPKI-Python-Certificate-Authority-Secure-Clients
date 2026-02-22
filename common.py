import json
import base64
import socket
import os
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def b64e(b):
    return base64.b64encode(b).decode("utf-8")

def b64d(s):
    return base64.b64decode(s.encode("utf-8"))

def now_utc_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def iso_plus_days(days):
    return (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat()

def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def send_json(sock, obj):
    data = canonical_json(obj)
    sock.sendall(len(data).to_bytes(4, "big") + data)

def recv_json(sock):
    hdr = recvn(sock, 4)
    if not hdr:
        raise ConnectionError("No data")
    n = int.from_bytes(hdr, "big")
    data = recvn(sock, n)
    return json.loads(data.decode("utf-8"))

def recvn(sock, n):
    chunks = []
    got = 0
    while got < n:
        part = sock.recv(n - got)
        if not part:
            return b""
        chunks.append(part)
        got += len(part)
    return b"".join(chunks)

def generate_ca_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def ca_public_pem(ca_priv):
    return ca_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def generate_client_x25519():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return priv, pub_raw

def x25519_shared_secret(my_priv, peer_pub_raw):
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_raw)
    return my_priv.exchange(peer_pub)

def build_cert_unsigned(subject_id, subject_pub_algo, subject_pub_b64, serial,
                        not_before, not_after, issuer_id, ca_pub_pem_b64):
    return {
        "subject_id": subject_id,
        "subject_public_key_info": {
            "algorithm_id": subject_pub_algo,
            "public_key_value_b64": subject_pub_b64,
        },
        "validity": {
            "not_before": not_before,
            "not_after": not_after,
        },
        "serial_number": serial,
        "issuer_id": issuer_id,
        "issuer_public_key_pem_b64": ca_pub_pem_b64,
    }

def sign_cert(ca_priv, cert_unsigned):
    to_sign = canonical_json(cert_unsigned)
    sig = ca_priv.sign(
        to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    cert = dict(cert_unsigned)
    cert["ca_signature_b64"] = b64e(sig)
    return cert

def verify_cert(cert):
    try:
        nb = datetime.fromisoformat(cert["validity"]["not_before"])
        na = datetime.fromisoformat(cert["validity"]["not_after"])
        t = datetime.now(timezone.utc)
        if not (nb <= t <= na):
            return False

        ca_pub_pem = b64d(cert["issuer_public_key_pem_b64"])
        ca_pub = serialization.load_pem_public_key(ca_pub_pem)

        unsigned = dict(cert)
        sig_b64 = unsigned.pop("ca_signature_b64", None)
        if not sig_b64:
            return False

        to_verify = canonical_json(unsigned)
        sig = b64d(sig_b64)

        ca_pub.verify(
            sig,
            to_verify,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def extract_subject_pubkey_raw(cert):
    return b64d(cert["subject_public_key_info"]["public_key_value_b64"])

def derive_master_key_km(shared_secret, context):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context)
    return hkdf.derive(shared_secret)

def derive_session_key_ks(master_key_km, nonce):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce, info=b"session-key")
    return hkdf.derive(master_key_km)

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    return b64e(iv + ciphertext)

def aes_decrypt(key, encrypted_data_b64):
    encrypted_data = b64d(encrypted_data_b64)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')