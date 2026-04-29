# =========================
# IMPORTS
# =========================

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os
import base64


# =========================
# CRIPTOGRAFIA (PGP SIMPLIFICADO)
# =========================

def gerar_chaves():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def criptografar_mensagem(mensagem, chave_publica_destino, chave_privada_remetente):
    chave_aes = os.urandom(32)
    iv = os.urandom(16)

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(mensagem.encode()) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(chave_aes),
        modes.CBC(iv),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()
    mensagem_criptografada = encryptor.update(padded_data) + encryptor.finalize()

    public_key = serialization.load_pem_public_key(chave_publica_destino)

    chave_aes_criptografada = public_key.encrypt(
        chave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    private_key = serialization.load_pem_private_key(
        chave_privada_remetente,
        password=None
    )

    assinatura = private_key.sign(
        mensagem.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return {
        'mensagem': base64.b64encode(mensagem_criptografada).decode(),
        'iv': base64.b64encode(iv).decode(),
        'chave_aes': base64.b64encode(chave_aes_criptografada).decode(),
        'assinatura': base64.b64encode(assinatura).decode()
    }


def descriptografar_mensagem(dados, chave_privada_destino, chave_publica_remetente):
    private_key = serialization.load_pem_private_key(
        chave_privada_destino,
        password=None
    )

    chave_aes = private_key.decrypt(
        base64.b64decode(dados['chave_aes']),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(
        algorithms.AES(chave_aes),
        modes.CBC(base64.b64decode(dados['iv'])),
        backend=default_backend()
    )

    decryptor = cipher.decryptor()
    padded_data = decryptor.update(
        base64.b64decode(dados['mensagem'])
    ) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    mensagem = unpadder.update(padded_data) + unpadder.finalize()
    mensagem = mensagem.decode()

    public_key = serialization.load_pem_public_key(chave_publica_remetente)

    try:
        public_key.verify(
            base64.b64decode(dados['assinatura']),
            mensagem.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        valido = True
    except:
        valido = False

    return mensagem, valido


# =========================
# RELÓGIO LÓGICO (LAMPORT)
# =========================

class LogicalClock:
    def __init__(self):
        self.time = 0

    def increment(self):
        self.time += 1
        return self.time

    def update(self, received_time):
        self.time = max(self.time, received_time) + 1
        return self.time


# =========================
# MENSAGEM
# =========================

class Message:
    def __init__(self, producer, consumer, channel, content, mode, timestamp):
        self.producer = producer
        self.consumer = consumer
        self.channel = channel
        self.content = content
        self.mode = mode  # unicast, multicast, broadcast
        self.timestamp_send = timestamp
        self.timestamp_receive = None


# =========================
# BUFFER DE MENSAGENS
# =========================

class MessageBuffer:
    def __init__(self):
        self.buffer = []

    def store(self, message):
        self.buffer.append(message)

    def consume(self, consumer_name, logical_time):
        for msg in self.buffer:
            if msg.consumer == consumer_name or msg.mode == "broadcast":
                msg.timestamp_receive = logical_time
                return msg
        return None


# =========================
# LOG
# =========================

def registrar_log(texto):
    with open("mensageria.log", "a", encoding="utf-8") as arquivo:
        arquivo.write(texto + "\n")


# =========================
# EXECUÇÃO (SIMULAÇÃO)
# =========================

if __name__ == "__main__":

    print("=== SISTEMA DE MENSAGERIA DISTRIBUÍDA ===\n")

    # relógios
    clock_Henrique = LogicalClock()
    clock_Luis = LogicalClock()

    # buffer
    buffer = MessageBuffer()

    # geração de chaves
    priv_Henrique, pub_Henrique = gerar_chaves()
    priv_Luis, pub_Luis = gerar_chaves()

    # envio
    mensagem_original = "Transferência realizada com sucesso"

    ts_envio = clock_Henrique.increment()

    pacote = criptografar_mensagem(
        mensagem_original,
        pub_Luis,
        priv_Henrique
    )

    mensagem = Message(
        producer="Henrique",
        consumer="Luis",
        channel="financeiro",
        content=pacote,
        mode="unicast",
        timestamp=ts_envio
    )

    buffer.store(mensagem)

    registrar_log(f"[PRODUCER] Henrique -> Luis | ts={ts_envio}")

    # consumo
    ts_receb = clock_Luis.update(ts_envio)

    msg_recebida = buffer.consume("Luis", ts_receb)

    mensagem_final, valido = descriptografar_mensagem(
        msg_recebida.content,
        priv_Luis,
        pub_Henrique
    )

    registrar_log(f"[CONSUMER] Luis recebeu de Henrique | ts={ts_receb}")

    # saída
    print("Mensagem final:", mensagem_final)
    print("Assinatura válida:", valido)
    print("Timestamp envio:", ts_envio)
    print("Timestamp recebimento:", ts_receb)