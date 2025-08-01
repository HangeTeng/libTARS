from core.crypto.public_params import PowerTable
from sage.all import Integer

def schnorr_proof(d, pp):
    r = pp.rand_int()
    T = pp.g1_table.multiply(Integer(r))
    c = pp.zr_hash(T)
    s = r + d * Integer(c)
    return (T, s)

def schnorr_verify(D, proof, pp):
    T, s = proof
    c = pp.zr_hash(T)
    return pp.g1_table.multiply(Integer(s)) == T + D * Integer(c)


def batch_schnorr_verify(D_list, proof_list, pp):
    if len(D_list) != len(proof_list):
        raise ValueError("D_list and proof_list must have the same length")
    
    s_sum = 0
    right_sum = pp.E(0)
    
    for i in range(len(D_list)):
        D = D_list[i]
        T, s = proof_list[i]
        c = pp.zr_hash(T)
        s_sum += Integer(s)
        right_sum += T + D * Integer(c)
    
    return pp.g1_table.multiply(s_sum) == right_sum