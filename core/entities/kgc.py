import json
import os
from core.crypto.public_params import load_kgc_params, point_to_string, point_from_string, PowerTable
from . import DEFAULT_PARAMS_PATH, DEFAULT_KGC_KEY_PATH, DEFAULT_TRACER_KEYS_FILE, DEFAULT_TRACER_SINGLE_KEY_FILE_FMT, DEFAULT_TRACER_SINGLE_PUBLIC_KEY_FILE_FMT, DEFAULT_TRACER_KEYS_DIR

class KGC:
    """
    KGC负责主密钥(s)、系统公钥(Q)的生成与校验，并负责tracer密钥的Shamir分发。
    Q和s均存储于key.json，Q也应与params.json一致，否则报错。
    用户密钥不由KGC生成，用户自行生成。
    现在支持生成新主密钥/公钥，并重新保存config的功能。
    """
    def __init__(self, params_path=DEFAULT_PARAMS_PATH, key_path=DEFAULT_KGC_KEY_PATH, load_key=True):
        self.params_path = params_path
        self.key_path = key_path
        # 加载曲线与协议参数
        self.pp = load_kgc_params(params_path)
        self.s = None

        if load_key:
            with open(params_path, 'r') as f:
                params = json.load(f)
            self.params = params
            params_g1 = None
            params_g2 = None
            params_Q = None
            if 'public_kgc_keys' in params and 'g1' in params['public_kgc_keys']:
                params_g1 = params['public_kgc_keys']['g1']
            if 'public_kgc_keys' in params and 'g2' in params['public_kgc_keys']:
                params_g2 = params['public_kgc_keys']['g2']
            if 'public_kgc_keys' in params and 'Q' in params['public_kgc_keys']:
                params_Q = params['public_kgc_keys']['Q']

            # 读取key.json中的g1, g2, Q和s
            if os.path.exists(key_path):
                with open(key_path, 'r') as f:
                    key_json = json.load(f)
                key_g1 = key_json.get("g1", None)
                key_g2 = key_json.get("g2", None)
                key_Q = key_json.get("Q", None)
                key_s = key_json.get("s", None)
                if key_g1 is None or key_g2 is None or key_Q is None or key_s is None:
                    raise ValueError("key.json must contain g1, g2, Q and s")
                self.pp.g1 = point_from_string(key_g1, self.pp.F, self.pp.E)
                self.pp.g2 = point_from_string(key_g2, self.pp.F, self.pp.E)
                self.pp.Q = point_from_string(key_Q, self.pp.F, self.pp.E)
                self.pp.g1_table = PowerTable(self.pp.g1)
                self.pp.g2_table = PowerTable(self.pp.g2)
                self.pp.Q_table = PowerTable(self.pp.Q)
                self.s = int(key_s)
            else:
                # 若无key.json，则新生成s和Q
                self.generate_master_key(save_config=True)
        else:
            # load_Q为False时，不做任何操作
            pass

        if load_key and params_g1 is not None and key_g1 != params_g1:
            raise ValueError(f"g1 mismatch: key.json g1={self.g1}, params.json g1={params_g1}")
        if load_key and params_g2 is not None and key_g2 != params_g2:
            raise ValueError(f"g2 mismatch: key.json g2={self.g2}, params.json g2={params_g2}")
        if load_key and params_Q is not None and key_Q != params_Q:
            raise ValueError(f"Q mismatch: key.json Q={self.Q}, params.json Q={params_Q}")

        # 追踪者密钥参数
        self.tracer_keys = {}

    @property
    def g1(self): return self.pp.g1
    @property
    def g2(self): return self.pp.g2
    @property
    def Q(self): return self.pp.Q
    @property
    def g1_table(self): return self.pp.g1_table
    @property
    def g2_table(self): return self.pp.g2_table
    @property
    def Q_table(self): return self.pp.Q_table

    @property
    def threshold_tracers(self): return self.pp.threshold_tracers
    @property
    def num_tracers(self): return self.pp.num_tracers

    def generate_master_key(self, save_key=True, save_public_params=False):
        """
        生成新的主密钥s和系统公钥g1, g2, Q，并保存到key.json。
        如果save_public_keys为True，则同步更新params.json中的g1, g2, Q。
        """
        self.s = self.pp.rand_int()
        self.pp.generate_kgc_keys(self.s)
        # 写入key.json
        if save_key:
            self.save_key(self.key_path)
        if save_public_params:
            self.save_public_keys()

    def save_key(self, key_path):
        """
        将当前g1, g2, Q, s写入key.json的g1, g2, Q, s字段
        """
        with open(key_path, 'w') as f:
            json.dump({"g1": point_to_string(self.g1), "g2": point_to_string(self.g2), "Q": point_to_string(self.Q), "s": int(self.s)}, f, indent=2)

    def save_public_keys(self):
        """
        将当前g1, g2, Q写入params.json的public_keys.g1, public_keys.g2, public_keys.Q字段
        """
        # 读取params.json
        if not hasattr(self, 'params'):
            with open(self.params_path, 'r') as f:
                params = json.load(f)
        else:
            params = self.params
        if 'public_kgc_keys' not in params:
            params['public_kgc_keys'] = {}
        params['public_kgc_keys']['g1'] = point_to_string(self.g1)
        params['public_kgc_keys']['g2'] = point_to_string(self.g2)
        params['public_kgc_keys']['Q'] = point_to_string(self.Q)
        with open(self.params_path, 'w') as f:
            json.dump(params, f, indent=2)
        self.params = params

    def generate_tracer_keys(self, save_all=True, save_single=True, tracer_keys_path=DEFAULT_TRACER_KEYS_FILE, single_key_file_fmt=DEFAULT_TRACER_SINGLE_KEY_FILE_FMT, single_public_key_file_fmt=DEFAULT_TRACER_SINGLE_PUBLIC_KEY_FILE_FMT):
        """
        生成所有追踪者的Shamir密钥份额，并为每个追踪者生成公钥g1_table*da_share
        trace id 从1开始
        """
        # 生成t-1个随机系数
        poly_coeffs = [self.s] + [self.pp.rand_int() for _ in range(self.threshold_tracers - 1)]
        # trace id 从1开始
        for trace_id in range(0, self.num_tracers):
            x_i = trace_id + 1 # 可以取其他坐标值，但需要保证x_i互不相同
            share = sum(poly_coeffs[j] * (x_i ** j) for j in range(self.threshold_tracers))
            share = int(share % int(self.pp.n))
            pub_share = self.g1_table.multiply(share)
            self.tracer_keys[trace_id] = {
                'tracer_id': trace_id,
                'x_i': x_i,
                'd_share': share,
                'pub_share': point_to_string(pub_share)
            }
        self.save_tracer_keys(save_all=save_all, save_single=save_single, tracer_keys_path=tracer_keys_path, single_key_file_fmt=single_key_file_fmt, single_public_key_file_fmt=single_public_key_file_fmt)
        return self.tracer_keys

    def save_tracer_keys(self, save_all=True, save_single=True, tracer_keys_path=DEFAULT_TRACER_KEYS_FILE, single_key_file_fmt=DEFAULT_TRACER_SINGLE_KEY_FILE_FMT, single_public_key_file_fmt=DEFAULT_TRACER_SINGLE_PUBLIC_KEY_FILE_FMT):
        """保存所有追踪者密钥，并为每个追踪者生成单独的密钥文件，包含公钥pub_share，同时为每个追踪者生成public版本（仅包含pub_share）"""
        import os
        serialized_keys = {}
        # 保存所有追踪者密钥到一个文件
        for tracer_id, key in self.tracer_keys.items():
            serialized_key = {
                'tracer_id': key['tracer_id'],
                'x_i': key['x_i'],
                'd_share': key['d_share'],
                'pub_share': key['pub_share']
            }
            serialized_keys[tracer_id] = serialized_key
        if save_all:
            with open(tracer_keys_path, 'w') as f:
                json.dump(serialized_keys, f, indent=2)
        # 额外为每个追踪者生成单独的密钥文件和public版本
        if save_single:
            for tracer_id, key in self.tracer_keys.items():
                single_key = {
                    'tracer_id': key['tracer_id'],
                    'x_i': key['x_i'],
                    'd_share': key['d_share'],
                    'pub_share': key['pub_share']
                }
                # public版本只包含tracer_id, x_i, pub_share
                public_key = {
                    'tracer_id': key['tracer_id'],
                    'x_i': key['x_i'],
                    'pub_share': key['pub_share']
                }
                # 根据filepath命名风格生成单个密钥文件名
                single_filename = single_key_file_fmt.format(tracer_id)
                public_filename = single_public_key_file_fmt.format(tracer_id)
                with open(single_filename, 'w') as f_single:
                    json.dump(single_key, f_single, indent=2)
                with open(public_filename, 'w') as f_public:
                    json.dump(public_key, f_public, indent=2)
    