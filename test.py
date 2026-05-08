# =========================
# TESTES
# =========================

from main import *

def testar_criptografia():
    print("\n[TESTE] Criptografia")

    priv_a, pub_a = CryptoPGP.gerar_chaves()
    priv_b, pub_b = CryptoPGP.gerar_chaves()

    msg = "Teste PGP"

    pub_keys = {"B": pub_b}

    pacote = CryptoPGP.encrypt(msg, pub_keys, priv_a)

    resultado, valido = CryptoPGP.decrypt(
        pacote,
        priv_b,
        pub_a,
        "B"  # 👈 importante
    )

    assert resultado == msg
    assert valido == True

    print("✔ Criptografia OK")


def testar_relogio():
    print("\n[TESTE] Relógio Lógico")

    clock1 = LogicalClock()
    clock2 = LogicalClock()

    t1 = clock1.tick()
    t2 = clock2.update(t1)

    assert t2 > t1

    print("✔ Relógio lógico OK")


def testar_buffer():
    print("\n[TESTE] Buffer")

    broker = MessageBroker()

    A = Client("A")
    B = Client("B")

    A.send(broker, "msg", [B], mode="unicast")

    msgs = broker.consume(B)

    assert len(msgs) > 0
    assert msgs[0].sender == "A"

    print("✔ Buffer OK")


def testar_fluxo_completo():
    print("\n[TESTE] Fluxo completo")

    broker = MessageBroker()

    A = Client("Henrique")
    B = Client("Luis")
    C = Client("Ana")

    pub_map = {
        "Henrique": A.pub,
        "Luis": B.pub,
        "Ana": C.pub
    }

    broker.register_channel("grupo1", ["Luis", "Ana"])

    # unicast
    A.send(broker, "Mensagem privada", [B], mode="unicast")

    # multicast
    A.send(broker, "Mensagem grupo", [B, C], channel="grupo1", mode="multicast")

    # broadcast (envia pra todos explicitamente)
    A.send(broker, "Mensagem global", [B, C], mode="broadcast")

    # consumo
    print("\n--- RECEBIMENTO ---\n")
    B.receive(broker, pub_map)
    C.receive(broker, pub_map)

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
# EXECUÇÃO
# =========================

if __name__ == "__main__":
    rodar_testes()