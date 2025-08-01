import json
import os
from sage.all import *
from sage.calculus.predefined import x
from sage.schemes.elliptic_curves.ell_point import EllipticCurvePoint
from collections import namedtuple
import hashlib

def load_system_params(params_file):
    """加载曲线和协议参数（不含公钥）"""
    with open(params_file, 'r') as f:
        params = json.load(f)
    curve = params['curve']
    protocol = params['protocol']
    threshold_tracers = protocol.get('threshold_tracers', None)
    num_tracers = protocol.get('num_tracers', None)
    return {
        'q': int(curve['q']),
        'a': int(curve['a']),
        'b': int(curve['b']),
        'n': int(curve['n']),
        'r': int(curve['r']),
        'k': int(curve['k']),
        'threshold_tracers': int(threshold_tracers),
        'num_tracers': int(num_tracers)
    }

def load_public_kgc_keys(params_file):
    """加载完整的公开参数（g1, g2, Q）"""
    with open(params_file, 'r') as f:
        params = json.load(f)
    public_kgc_keys = params.get('public_kgc_keys', None)
    if public_kgc_keys is None:
        raise ValueError("public_kgc_keys not found in params.json")
    
    # 检查必需的参数
    required_params = ['g1', 'g2', 'Q']
    for param in required_params:
        if param not in public_kgc_keys:
            raise ValueError(f"{param} not found in public_kgc_keys")
    
    return public_kgc_keys

def point_from_string(point_str, F, E):
    """从字符串恢复椭圆曲线点，标准格式为 '(x, y)'，x和y为数字或可被F解析的字符串"""
    point_str = point_str.strip('()').replace(' ', '')
    coords = point_str.split(',')
    if len(coords) != 2:
        raise ValueError(f"Invalid point string: {point_str}")
    x_coord = F(coords[0])
    y_coord = F(coords[1])
    return E(x_coord, y_coord)

def point_to_string(point):
    """标准化椭圆曲线点到字符串，格式为 '(x, y)'，x和y为数字字符串"""
    if hasattr(point, 'xy'):
        x, y = point.xy()
    elif isinstance(point, tuple) and len(point) == 2:
        x, y = point
    else:
        raise ValueError(f"Invalid point object: {point}")
    return f"({x},{y})"

class CurveContext:
    """曲线上下文，包含有限域、曲线、Frobenius等"""
    def __init__(self, params):
        self.q = params['q']
        self.a = params['a']
        self.b = params['b']
        self.n = params['n']
        self.r = params['r']
        self.k = params['k']
        self.threshold_tracers = params['threshold_tracers']
        self.num_tracers = params['num_tracers']
        self.F = GF(self.q ** self.k, modulus=x ** self.k + x + 1, name='a')
        self.E = EllipticCurve(self.F, [self.a, self.b])
        self.Frob = [self.F.frobenius_endomorphism(i) for i in range(self.k)]
        self.ModRing = IntegerModRing(self.n)

    def pairing(self, e1, e2):
        r = Integer(self.r)
        return e1.weil_pairing(e2, r)

    def rand_int(self):
        return self.ModRing.random_element()

    def zr_hash(self, element):
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



class PublicParams:
    """
    公开系统参数类
    - KGC: 只需曲线参数, 由曲线计算g1/g2, 不加载kgc_pk
    - User/Tracer: 需曲线参数, 由曲线计算g1/g2, 并从param加载kgc_pk
    """
    def __init__(self, params_file, load_kgc_key=True):
        params = load_system_params(params_file)
        self.ctx = CurveContext(params)
        if load_kgc_key:
            public_kgc_keys = load_public_kgc_keys(params_file)
            self.g1 = point_from_string(public_kgc_keys['g1'], self.ctx.F, self.ctx.E)
            self.g2 = point_from_string(public_kgc_keys['g2'], self.ctx.F, self.ctx.E)
            self.Q = point_from_string(public_kgc_keys['Q'], self.ctx.F, self.ctx.E)
            self.g1_table = PowerTable(self.g1)
            self.g2_table = PowerTable(self.g2)
            self.Q_table = PowerTable(self.Q)
        else:
            self.g1 = None
            self.g2 = None
            self.Q = None
            self.g1_table = None
            self.g2_table = None
            self.Q_table = None
        # 环签名相关
        self.R = namedtuple("Member", "public_key public_id")

    # 代理CurveContext的常用属性和方法
    @property
    def F(self): return self.ctx.F
    @property
    def E(self): return self.ctx.E
    @property
    def Frob(self): return self.ctx.Frob
    @property
    def ModRing(self): return self.ctx.ModRing
    @property
    def q(self): return self.ctx.q
    @property
    def a(self): return self.ctx.a
    @property
    def b(self): return self.ctx.b
    @property
    def n(self): return self.ctx.n
    @property
    def r(self): return self.ctx.r
    @property
    def k(self): return self.ctx.k
    @property
    def threshold_tracers(self): return self.ctx.threshold_tracers
    @property
    def num_tracers(self): return self.ctx.num_tracers

    def pairing(self, e1, e2): return self.ctx.pairing(e1, e2)
    def rand_int(self): return self.ctx.rand_int()
    def zr_hash(self, element): return self.ctx.zr_hash(element)

    def generate_kgc_keys(self, s=None):
        """
        由曲线参数计算g1, g2, Q
        """
        # 生成元的选取和轨迹计算应与KGC一致
        ord = self.E.order() // (self.n ** 2)
        g = self.E.random_point()
        while (g * ord).is_zero():
            g = self.E.random_point()
        g = g * ord
        # 迹
        self.g1 = g
        for i in range(1, self.k):
            X = self.Frob[i](g[0])
            Y = self.Frob[i](g[1])
            self.g1 += self.E(X, Y)
        self.g2 = self.k * g - self.g1
        s = self.rand_int() if s is None else s
        self.Q = s * self.g1
        self.g1_table = PowerTable(self.g1)
        self.g2_table = PowerTable(self.g2)
        self.Q_table = PowerTable(self.Q)
        return self.g1, self.g2, self.Q, s

class PowerTable:
    """预计算表，用于加速椭圆曲线点乘法"""
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
        """使用预计算表进行点乘法"""
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

# 用于KGC生成密钥时（不加载kgc_pk）
def load_kgc_params(params_file=None):
    """KGC专用：只加载曲线参数, 由曲线计算g1/g2, 不加载kgc_pk"""
    pp = PublicParams(params_file, load_kgc_key=False)
    return pp

# 用于User/Tracer等加载全部公钥参数
def load_full_public_params(params_file=None):
    """User/Tracer等：加载曲线参数, 由曲线计算g1/g2, 并加载kgc_pk"""
    pp = PublicParams(params_file, load_kgc_key=True)
    return pp