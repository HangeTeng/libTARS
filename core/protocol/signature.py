from core.entities.user import User, Ring
from core.entities.tracer import Tracer
from core.crypto.base import pp, g1_table, PowerTable, E
from core.crypto.nizk import verify_ring_proof
from time import time

def demo_ring_signature(message=b"important message"):
    users = [User() for _ in range(10)]
    tracers = [Tracer(i) for i in range(pp.n_tracers)]
    signer = users[4]

    clock = time()
    cipher, proof, C2_table = signer.sign(message)
    print("signing time:", time() - clock)

    clock = time()
    assert verify_ring_proof(C2_table, proof, message), "环签名验证失败"
    print("signature verification time:", time() - clock)

    return users, tracers, cipher, proof, C2_table
