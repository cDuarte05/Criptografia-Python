from crypto_utils import *

# luis
priv_luis, pub_luis = gerar_chaves()

# henrique
priv_henrique, pub_henrique = gerar_chaves()

mensagem = "Transferência aprovada com sucesso"

print("Mensagem original:", mensagem)

pacote = criptografar_mensagem(
    mensagem,
    pub_henrique,
    priv_luis
)

mensagem_final, assinatura_valida = descriptografar_mensagem(
    pacote,
    priv_henrique,
    pub_luis
)

print("Mensagem descriptografada:", mensagem_final)
print("Assinatura válida:", assinatura_valida)