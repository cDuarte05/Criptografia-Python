if __name__ == "__main__":

    broker = MessageBroker()

    # clientes
    A = Client("Henrique")
    B = Client("Luis")
    C = Client("Ana")

    # mapa de chaves públicas
    pub_map = {
        "Henrique": A.pub,
        "Luis": B.pub,
        "Ana": C.pub
    }

    # canal multicast
    broker.register_channel("grupo1", ["Luis", "Ana"])

    # unicast
    A.send(broker, "Mensagem privada", [B], mode="unicast")

    # multicast
    A.send(broker, "Mensagem grupo", [B, C], channel="grupo1", mode="multicast")

    # broadcast
    A.send(broker, "Mensagem global", mode="broadcast")

    print("\n--- RECEBIMENTO ---\n")

    B.receive(broker, pub_map)
    C.receive(broker, pub_map)