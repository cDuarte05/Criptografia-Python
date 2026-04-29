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