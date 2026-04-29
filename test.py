from crypto_utils import *

priv_a, pub_a = gerar_chaves()
priv_b, pub_b = gerar_chaves()

msg = "Teste de segurança PGP"

pacote = criptografar_mensagem(msg, pub_b, priv_a)
resultado, valido = descriptografar_mensagem(pacote, priv_b, pub_a)

assert resultado == msg
assert valido == True

print("Teste executado com sucesso")