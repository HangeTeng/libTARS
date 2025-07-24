from core.crypto.base import pp, g1_table, E
from core.crypto.schnorr import schnorr_proof
from sage.all import Integer, inverse_mod

modulus = int(pp.ModRing.order())

class Tracer:
    def __init__(self, index):
        self.index = index
        self.x_i, self.d_share = pp.d_shares[index]
        self.proof = None

    def partial_decrypt(self, C1_table):
        s_i = C1_table.multiply(self.d_share)
        proof = schnorr_proof(self.d_share)
        return s_i, proof

    @classmethod
    def combine(cls, shares, C2):
        x_list = [x_i for (_, x_i) in shares]
        s_points = [s_i_point for (s_i_point, _) in shares]
        inverses = {}
        for i in range(len(shares)):
            denominator = 1
            for j in range(len(shares)):
                if i != j:
                    denominator *= (x_list[i] - x_list[j]) % modulus
            inverses[i] = inverse_mod(denominator, modulus)
        result_point = E(0)
        for i in range(len(shares)):
            numerator = 1
            for j in range(len(shares)):
                if i != j:
                    numerator *= x_list[j] % modulus
            lambda_i = (numerator * inverses[i]) % modulus
            result_point += s_points[i] * Integer(lambda_i)
        return C2 - result_point
