from core.protocol.signature import demo_ring_signature
from core.protocol.trace import demo_trace
from core.crypto.base import pp, g1_table, E
from core.crypto.nizk import verify_ring_proof
from time import time

def main():
    users, tracers, cipher, proof, C2_table = demo_ring_signature()
    pid, proof_tracers = demo_trace(cipher, tracers)

    clock = time()
    s_sum = 0
    right = E(0)
    for i in range(pp.t):
        T, s = proof_tracers[i]
        c = pp.Zr_hash(T)
        s_sum += s
        right += T + g1_table.multiply(tracers[i].d_share) * int(c)
    assert g1_table.multiply(s_sum) == right, "分组解密证明无效"
    print("trace verification time:", time() - clock)

    cipher_2, proof_2, table = users[4].sign(b"important message")
    clock = time()
    if cipher_2[2] == cipher[2]:
        print("属于同一来源")
    else:
        print("不属于同一来源")
    print("link time", time() - clock)

if __name__ == "__main__":
    main()
