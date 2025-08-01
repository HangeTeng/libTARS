from core.crypto.base import pp, g1_table, PowerTable, E
from core.entities.tracer import Tracer
from time import time

def demo_trace(cipher, tracers):
    shares = []
    proof_tracers = []
    C1_table = PowerTable(cipher[0])
    clock = time()
    for i in range(pp.t):
        s_i, proof_i = tracers[i].partial_decrypt(C1_table)
        shares.append((s_i, tracers[i].x_i))
        proof_tracers.append(proof_i)
    pid = Tracer.combine(shares, cipher[1])
    print("trace time:", time() - clock)
    return pid, proof_tracers
