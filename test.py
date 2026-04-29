# =========================
# TESTES
# =========================

def testar_criptografia():
    print("\n[TESTE] Criptografia")

    priv_a, pub_a = gerar_chaves()
    priv_b, pub_b = gerar_chaves()

    msg = "Teste PGP"

    pacote = criptografar_mensagem(msg, pub_b, priv_a)
    resultado, valido = descriptografar_mensagem(pacote, priv_b, pub_a)

    assert resultado == msg
    assert valido == True

    print("✔ Criptografia OK")


def testar_relogio():
    print("\n[TESTE] Relógio Lógico")

    clock1 = LogicalClock()
    clock2 = LogicalClock()

    t1 = clock1.increment()
    t2 = clock2.update(t1)

    assert t2 > t1

    print("✔ Relógio lógico OK")


def testar_buffer():
    print("\n[TESTE] Buffer")

    buffer = MessageBuffer()
    clock = LogicalClock()

    msg = Message("Henrique", "Luis", "canal", "conteudo", "unicast", 1)

    buffer.store(msg)

    recebido = buffer.consume("Luis", clock.increment())

    assert recebido is not None
    assert recebido.consumer == "Luis"

    print("✔ Buffer OK")


def testar_fluxo_completo():
    print("\n[TESTE] Fluxo completo")

    clock_a = LogicalClock()
    clock_b = LogicalClock()
    buffer = MessageBuffer()

    priv_a, pub_a = gerar_chaves()
    priv_b, pub_b = gerar_chaves()

    msg = "Fluxo completo funcionando"

    ts_envio = clock_a.increment()

    pacote = criptografar_mensagem(msg, pub_b, priv_a)

    message = Message("Henrique", "Luis", "canal", pacote, "unicast", ts_envio)

    buffer.store(message)

    ts_receb = clock_b.update(ts_envio)

    msg_recebida = buffer.consume("Luis", ts_receb)

    resultado, valido = descriptografar_mensagem(
        msg_recebida.content,
        priv_b,
        pub_a
    )

    assert resultado == msg
    assert valido == True

    print("✔ Fluxo completo OK")


def rodar_testes():
    print("\n=========================")
    print("EXECUTANDO TESTES")
    print("=========================")

    testar_criptografia()
    testar_relogio()
    testar_buffer()
    testar_fluxo_completo()

    print("\n✔ TODOS OS TESTES PASSARAM")


# =========================
# CHAMADA DOS TESTES
# =========================

if __name__ == "__main__":
    rodar_testes()