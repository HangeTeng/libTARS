from core.crypto.base import pp, g1_table
from sage.all import Integer

def schnorr_proof(d):
    r = pp.RandInt()
    T = g1_table.multiply(Integer(r))
    c = pp.Zr_hash(T)
    s = r + d * Integer(c)
    return (T, s)

def schnorr_verify(D, proof):
    T, s = proof
    c = pp.Zr_hash(T)
    return g1_table.multiply(Integer(s)) == T + D * Integer(c)
