import os
import base64
from collections import defaultdict

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


# =========================
# CRIPTOGRAFIA (PGP)
# =========================

class CryptoPGP:

    @staticmethod
    def gerar_chaves():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        return (
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ),
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    @staticmethod
    def encrypt(msg, pub_dest, priv_sender):
        chave_aes = os.urandom(32)
        iv = os.urandom(16)

        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(msg.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(chave_aes), modes.CBC(iv))
        encrypted = cipher.encryptor().update(padded) + cipher.encryptor().finalize()

        pub = serialization.load_pem_public_key(pub_dest)

        enc_key = pub.encrypt(
            chave_aes,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        priv = serialization.load_pem_private_key(priv_sender, password=None)

        signature = priv.sign(
            msg.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return {
            "data": base64.b64encode(encrypted).decode(),
            "iv": base64.b64encode(iv).decode(),
            "key": base64.b64encode(enc_key).decode(),
            "sig": base64.b64encode(signature).decode()
        }

    @staticmethod
    def decrypt(pkg, priv_dest, pub_sender):
        priv = serialization.load_pem_private_key(priv_dest, password=None)

        aes = priv.decrypt(
            base64.b64decode(pkg["key"]),
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(
            algorithms.AES(aes),
            modes.CBC(base64.b64decode(pkg["iv"]))
        )

        padded = cipher.decryptor().update(base64.b64decode(pkg["data"])) + cipher.decryptor().finalize()

        unpad = sym_padding.PKCS7(128).unpadder()
        msg = (unpad.update(padded) + unpad.finalize()).decode()

        pub = serialization.load_pem_public_key(pub_sender)

        try:
            pub.verify(
                base64.b64decode(pkg["sig"]),
                msg.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            valid = True
        except:
            valid = False

        return msg, valid


# =========================
# RELÓGIO LÓGICO
# =========================

class LogicalClock:
    def __init__(self):
        self.time = 0

    def tick(self):
        self.time += 1
        return self.time

    def update(self, t):
        self.time = max(self.time, t) + 1
        return self.time


# =========================
# LOGGER
# =========================

def log(msg):
    with open("log.txt", "a") as f:
        f.write(msg + "\n")


# =========================
# MESSAGE
# =========================

class Message:
    def __init__(self, sender, receivers, channel, content, mode, ts):
        self.sender = sender
        self.receivers = receivers
        self.channel = channel
        self.content = content
        self.mode = mode
        self.ts_send = ts
        self.ts_receive = {}


# =========================
# BROKER (BUFFER DISTRIBUÍDO)
# =========================

class MessageBroker:

    def __init__(self):
        self.messages = []
        self.channels = defaultdict(list)

    def register_channel(self, channel, clients):
        self.channels[channel] = clients

    def publish(self, message):
        self.messages.append(message)

        log(f"[SEND] {message.sender} -> {message.mode} | ts={message.ts_send}")

    def consume(self, client):
        msgs = []

        for m in sorted(self.messages, key=lambda x: x.ts_send):

            if m.mode == "broadcast":
                msgs.append(m)

            elif m.mode == "multicast" and client.name in self.channels[m.channel]:
                msgs.append(m)

            elif m.mode == "unicast" and client.name in m.receivers:
                msgs.append(m)

        return msgs


# =========================
# CLIENTE (NÓ DISTRIBUÍDO)
# =========================

class Client:

    def __init__(self, name):
        self.name = name
        self.clock = LogicalClock()
        self.priv, self.pub = CryptoPGP.gerar_chaves()

    def send(self, broker, msg, receivers=None, channel=None, mode="unicast"):
        ts = self.clock.tick()

        pkg = CryptoPGP.encrypt(msg, receivers[0].pub if receivers else self.pub, self.priv)

        m = Message(self.name, [r.name for r in receivers] if receivers else [], channel, pkg, mode, ts)

        broker.publish(m)

    def receive(self, broker, sender_pub_map):
        messages = broker.consume(self)

        for m in messages:
            ts = self.clock.update(m.ts_send)

            pub_sender = sender_pub_map[m.sender]

            msg, valid = CryptoPGP.decrypt(m.content, self.priv, pub_sender)

            log(f"[RECV] {self.name} <- {m.sender} | ts={ts} | valid={valid}")

            print(f"{self.name} recebeu: {msg}")