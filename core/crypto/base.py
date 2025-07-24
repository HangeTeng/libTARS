import json
import os
from sage.all import *
from sage.calculus.predefined import x
from sage.schemes.elliptic_curves.ell_point import EllipticCurvePoint
from collections import namedtuple
import hashlib
import random

# 读取系统参数
PARAMS_PATH = os.path.join(os.path.dirname(__file__), '../config/params.json')
with open(PARAMS_PATH, 'r') as f:
    params = json.load(f)

curve = params['curve']
protocol = params['protocol']

q = curve['q']
a = curve['a']
b = curve['b']
n = curve['n']
r = curve['r']
k = protocol['k']
t = protocol['t']
n_tracers = protocol['n_tracers']

F = GF(q ** k, modulus=x ** k + x + 1, name='a')
E = EllipticCurve(F, [a, b])
Frob = [F.frobenius_endomorphism(i) for i in range(k)]

R = namedtuple("Member", "public_key public_id")
Ring = []
Ring_table = []

def pairing(e1, e2):
    global r
    r = Integer(r)
    return e1.weil_pairing(e2, r)

class GenPP:
    def __init__(self):
        ord = E.order() / n ** 2
        ord = Integer(ord)
        g = E.random_point()
        while (g * ord).is_zero():
            g = E.random_point()
        g = g * ord
        self.g1 = self.Trace(g)
        self.g2 = k * g - self.g1

        self.ModRing = IntegerModRing(n)

        self.t = t
        self.n_tracers = n_tracers
        s = random.randint(1, n)
        self.Q = s * self.g1
        poly_coeffs = [s] + [random.randint(1, n) for _ in range(self.t - 1)]
        self.d_shares = []
        for i in range(1, self.n_tracers + 1):
            share = sum(poly_coeffs[j] * (i) ** j for j in range(self.t))
            self.d_shares.append((i, share))

    def Trace(self, P):
        Q = P
        for i in range(1, k):
            X = Frob[i](P[0])
            Y = Frob[i](P[1])
            Q += E(X, Y)
        return Q

    def RandInt(self):
        return self.ModRing.random_element()

    def Zr_hash(self, element):
        def process_point(point):
            x = point.xy()[0].polynomial().coefficients()
            y = point.xy()[1].polynomial().coefficients()
            return b''.join([c.to_bytes(32, 'big') for c in x + y])

        message = b''
        if isinstance(element, tuple):
            for item in element:
                if isinstance(item, EllipticCurvePoint):
                    message += process_point(item)
                else:
                    message += str(item).encode()
        else:
            try:
                element.decode()
                message = element
            except AttributeError:
                if isinstance(element, EllipticCurvePoint):
                    message = process_point(element)
                else:
                    message = str(element).encode()

        digest = hashlib.sha224()
        digest.update(message)
        hash_value = digest.digest()
        return self.ModRing(int.from_bytes(hash_value, 'big'))

class PowerTable:
    def __init__(self, P, window_size=4, max_bits=450):
        self.window_size = window_size
        self.table = []
        current = P
        num_blocks = (max_bits + window_size - 1) // window_size
        for _ in range(num_blocks):
            block = [current * i for i in range(1 << window_size)]
            self.table.append(block)
            for _ in range(window_size):
                current = current * 2

    def multiply(self, k):
        result = self.table[0][0]
        k_bin = bin(k)[2:]
        padding = (-len(k_bin)) % self.window_size
        k_padded = '0' * padding + k_bin
        num_blocks = len(k_padded) // self.window_size
        for block_idx in range(num_blocks):
            start = len(k_padded) - (block_idx + 1) * self.window_size
            end = len(k_padded) - block_idx * self.window_size
            window = k_padded[start:end]
            idx = int(window, 2)
            result += self.table[block_idx][idx]
        return result

# 全局系统参数实例
pp = GenPP()
g1_table = PowerTable(pp.g1)
Q_table = PowerTable(pp.Q)
