from core.crypto.base import pp, Ring, R, g1_table, Q_table, PowerTable, Ring_table
from core.crypto.nizk import ring_proof
from sage.all import Integer

class User:
    def __init__(self):
        self.sk = pp.RandInt()
        self.pk = pp.g2 * Integer(self.sk)
        self.pid = g1_table.multiply(Integer(self.sk))
        self.event_hash = pp.Zr_hash(self.pid)
        self.index = len(Ring)
        Ring.append(R(self.pk, self.pid))
        Ring_table.append(PowerTable(self.pid))

    def sign(self, message):
        index = 5
        k = pp.RandInt()
        k_int = Integer(k)
        C1 = g1_table.multiply(k_int)
        C2 = self.pid + Q_table.multiply(k_int)
        T = g1_table.multiply(Integer(self.event_hash))
        PID_encryption = (C1, C2, T)
        C2_table = PowerTable(C2, window_size=2)
        PID_signature = ring_proof(index, Integer(self.sk), k_int, C2, message, C2_table)
        return PID_encryption, PID_signature, C2_table
