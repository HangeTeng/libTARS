from core.crypto.base import pp, g1_table, Q_table, Ring, Ring_table, E
from sage.all import Integer

def simulate(i, c, C2_table):
    pid_mul_c = Ring_table[i].multiply(c)
    res_sch = Integer(pp.RandInt())
    com_sch = g1_table.multiply(res_sch) - pid_mul_c
    res_oka = Integer(pp.RandInt())
    com_oka = Q_table.multiply(res_oka) - C2_table.multiply(c) + pid_mul_c
    return com_sch, res_sch, com_oka, res_oka

def ring_proof(index, sk, k_int, C2, message, C2_table):
    Len_Ring = len(Ring)
    commit_schnorr, commit_okamoto = ([None] * Len_Ring, [None] * Len_Ring)
    challenge = []
    response_schnorr, response_okamoto = ([None] * Len_Ring, [None] * Len_Ring)
    c_sum = 0
    c = pp.Zr_hash(message)

    for i in range(Len_Ring):
        challenge.append(Integer(pp.RandInt()))
        commit_schnorr[i], response_schnorr[i], commit_okamoto[i], response_okamoto[i] = simulate(i, challenge[i], C2_table)
        if i != index-1:
            c_sum = c_sum ^ challenge[i]
            c *= pp.Zr_hash(commit_schnorr[i]) * pp.Zr_hash(commit_okamoto[i])

    u = Integer(pp.RandInt())
    commit_schnorr[index-1] = g1_table.multiply(u)
    commit_okamoto[index-1] = Q_table.multiply(u)

    c *= pp.Zr_hash(commit_schnorr[index-1]) * pp.Zr_hash(commit_okamoto[index-1])
    challenge[index-1] = Integer(c) ^ c_sum

    response_schnorr[index-1] = sk * challenge[index-1] + u
    response_okamoto[index-1] = Integer(k_int * challenge[index-1] + u)

    return [(commit_schnorr, commit_okamoto), challenge[:-1], (response_schnorr, response_okamoto)]

def verify_ring_proof(C2_table, proof, message):
    (commit_schnorr, commit_okamoto), challenge, (response_schnorr, response_okamoto) = proof

    c_sum = 0
    c = pp.Zr_hash(message)

    for com in commit_schnorr:
        c *= pp.Zr_hash(com)
    for com in commit_okamoto:
        c *= pp.Zr_hash(com)

    challenge_sum = 0
    c = Integer(c)
    for ch in challenge:
        c_sum = c_sum ^ ch
        challenge_sum += ch
    challenge.append(Integer(c) ^ c_sum)
    challenge_sum += Integer(c) ^ c_sum

    res_sch_sum = 0
    res_oka_sum = 0
    pid_mul_c_sum = E(0)
    com_sch_sum = E(0)
    com_oka_sum = E(0)
    for i in range(len(Ring)):
        pid_mul_c_sum += Ring_table[i].multiply(challenge[i])
        com_sch_sum += commit_schnorr[i]
        com_oka_sum += commit_okamoto[i]
        res_oka_sum += response_okamoto[i]
        res_sch_sum += response_schnorr[i]
    left_sch = g1_table.multiply(res_sch_sum)
    left_oka = Q_table.multiply(res_oka_sum)
    right_sch = pid_mul_c_sum + com_sch_sum
    right_oka = C2_table.multiply(challenge_sum) + com_oka_sum - pid_mul_c_sum
    return left_sch == right_sch and left_oka == right_oka
