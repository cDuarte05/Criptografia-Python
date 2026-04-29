from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os
import base64


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
    return mensagem, valido