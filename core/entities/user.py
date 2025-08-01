from inspect import Signature
import os
import json
from core.crypto.public_params import load_full_public_params, point_from_string, point_to_string, PowerTable, point_to_string
from core.crypto.nizk import ring_proof, verify_ring_proof
from sage.all import Integer
import hashlib
from . import DEFAULT_USER_SINGLE_KEY_FILE_FMT, DEFAULT_USER_SINGLE_PUBLIC_KEY_FILE_FMT, DEFAULT_PARAMS_PATH, DEFAULT_USER_KEYS_DIR

class User:
    def __init__(self, user_id, params_file=DEFAULT_PARAMS_PATH, key_file=None, load_key=True):
        """
        初始化用户，可指定公共参数文件和密钥文件。
        :param user_id: 用户ID
        :param params_file: 公共参数文件路径
        :param key_file: 用户密钥文件路径
        :param load_key: 是否加载密钥（可选）
        """
        self.user_id = str(user_id)
        self.key_file = key_file or DEFAULT_USER_SINGLE_KEY_FILE_FMT.format(self.user_id)
        self.public_key_file = DEFAULT_USER_SINGLE_PUBLIC_KEY_FILE_FMT.format(self.user_id)
        self.params_file = params_file or DEFAULT_PARAMS_PATH

        self.pp = load_full_public_params(self.params_file)
        self.sk = None
        self.pk = None
        self.pid = None

        if load_key:
            self.load_key(self.key_file)
    
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
    def F(self): return self.pp.F
    @property
    def E(self): return self.pp.E

    def load_key(self, key_file=None):
        """从文件加载用户密钥"""
        key_file = key_file or self.key_file
        try:
            with open(key_file, 'r') as f:
                key_data = json.load(f)
            # 处理单个密钥文件或批量密钥文件
            if 'user_id' in key_data:
                key_info = key_data
            else:
                if str(self.user_id) not in key_data:
                    raise ValueError(f"User {self.user_id} not found in key file")
                key_info = key_data[str(self.user_id)]
            self.sk = Integer(key_info['sk'])
            # 使用 point_from_string 加载点
            self.pk = point_from_string(key_info['pk'], self.F, self.E)
            self.pid = point_from_string(key_info['pid'], self.F, self.E)
        except FileNotFoundError:
            raise FileNotFoundError(f"User key file {key_file} not found. Please generate keys first.")
        except KeyError as e:
            raise ValueError(f"Invalid key file format: missing {e}")

    def generate_key(self, save_key=True):
        """生成用户密钥对并保存到文件（不包含event_hash）"""
        
        self.sk = self.pp.rand_int()
        self.pk = self.g2_table.multiply(Integer(self.sk))
        self.pid = self.g1_table.multiply(Integer(self.sk))
        if save_key:
            self.save_key()

    def save_key(self, key_file=None, public_key_file=None):
        """
        将当前用户密钥保存到文件（不包含event_hash）。
        同时可选地保存一个不含sk的public版本（public_key_file指定路径）。
        """
        key_file = key_file or self.key_file
        public_key_file = public_key_file or self.public_key_file
        # 使用 point_to_string 存储点
        key_data = {
            "user_id": self.user_id,
            "sk": int(self.sk),
            "pk": point_to_string(self.pk),
            "pid": point_to_string(self.pid)
        }
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        with open(key_file, 'w') as f:
            json.dump(key_data, f, indent=2)
        if public_key_file is not None: # 保存public版本（不含sk），如指定public_key_file
            public_data = {
                "user_id": self.user_id,
                "pk": point_to_string(self.pk),
                "pid": point_to_string(self.pid)
            }
            os.makedirs(os.path.dirname(public_key_file), exist_ok=True)
            with open(public_key_file, 'w') as f:
                json.dump(public_data, f, indent=2)

    def load_ring(self, user_ids, user_dir=DEFAULT_USER_KEYS_DIR):
        """
        根据用户ID集合或列表文件，加载环签名环。
        :param user_ids: 用户ID列表或包含用户ID的文件路径
        :param user_dir: 用户密钥文件所在目录
        :return: (Ring, Ring_table, id2index)
        """
        if isinstance(user_ids, str) and os.path.isfile(user_ids):
            # 如果是文件，逐行读取用户ID
            with open(user_ids, 'r') as f:
                user_ids = [line.strip() for line in f if line.strip()]
        user_ids = [str(uid) for uid in user_ids]
        Ring = []
        Ring_table = []
        id2index = {}
        for idx, uid in enumerate(user_ids):
            key_file = os.path.join(user_dir, DEFAULT_USER_SINGLE_PUBLIC_KEY_FILE_FMT.format(uid))
            try:
                with open(key_file, 'r') as f:
                    key_data = json.load(f)
                if 'user_id' in key_data:
                    key_info = key_data
                else:
                    key_info = key_data[uid]
                # 使用 point_from_string 加载点
                pk = point_from_string(key_info['pk'], self.pp.F, self.pp.E)
                pid = point_from_string(key_info['pid'], self.pp.F, self.pp.E)
                Ring.append(self.pp.R(pk, pid))
                Ring_table.append(PowerTable(pid))
                id2index[uid] = idx + 1
            except Exception as e:
                raise RuntimeError(f"Failed to load user key for {uid}: {e}")
        return Ring, Ring_table, id2index

    def sign(self, message, ring_user_ids, event="default", user_dir=DEFAULT_USER_KEYS_DIR):
        """
        生成环签名。根据输入的用户ID集合或列表文件构建环。
        :param message: 签名消息
        :param ring_user_ids: 用户ID列表或文件
        :param event: 用于签名的event字段（将对其取hash）
        :return: (PID_encryption, PID_signature, C2_table, ring_user_ids)
        """
        # 计算event字段的hash，作为event_hash
        if isinstance(event, str):
            event_bytes = event.encode('utf-8')
        else:
            event_bytes = bytes(event)
        event_hash = int(hashlib.sha256(event_bytes).hexdigest(), 16)

        Ring, Ring_table, id2index = self.load_ring(ring_user_ids, user_dir)
        if self.user_id not in id2index:
            raise ValueError(f"Current user_id {self.user_id} not in ring_user_ids")
        index = id2index[self.user_id]
        k = self.pp.rand_int()
        k_int = Integer(k)
        C1 = self.g1_table.multiply(k_int)
        C2 = self.pid + self.Q_table.multiply(k_int)
        T = self.g1_table.multiply(Integer(event_hash))
        PID_encryption = (C1, C2, T)
        C2_table = PowerTable(C2, window_size=2)
        # ring_proof的输入
        # 按nizk.py接口补全参数
        PID_signature = ring_proof(
            index, Integer(self.sk), k_int, message, C2_table, Ring_table, self.pp
        )
        return (PID_encryption, PID_signature)

    def verify(self, message, signature, ring_user_ids, event="default", user_dir=None):
        """
        验证环签名。
        :param message: 被签名的消息
        :param PID_encryption: (C1, C2, T) 三元组
        :param PID_signature: 签名证明
        :param ring_user_ids: 用户ID列表或文件
        :param event: event字段（需与签名时一致）
        :return: True/False
        """
        PID_encryption, PID_signature = signature

        # 计算event字段的hash
        if isinstance(event, str):
            event_bytes = event.encode('utf-8')
        else:
            event_bytes = bytes(event)
        event_hash = int(hashlib.sha256(event_bytes).hexdigest(), 16)

        # 加载环
        Ring, Ring_table, id2index = self.load_ring(ring_user_ids, user_dir)

        # 解析PID_encryption
        C1, C2, T = PID_encryption
        # 检查T是否等于g1^event_hash
        expected_T = self.g1_table.multiply(Integer(event_hash))
        if T != expected_T:
            return False

        # 构造C2_table
        C2_table = PowerTable(C2, window_size=2)
        # 按nizk.py接口补全参数
        return verify_ring_proof(
            C2_table, PID_signature, message, Ring_table, self.pp
        )

        # INSERT_YOUR_CODE

    @staticmethod
    def serialize_signature(signature):
        """
        将签名结果序列化为字符串（适合写入json等）。
        - PID_encryption: (C1, C2, T) 三元组（点对象）
        - PID_signature: nizk.py的proof格式
        返回: dict，所有点都转为字符串
        """

        PID_encryption, PID_signature = signature
        # PID_encryption: (C1, C2, T)
        enc_str = [point_to_string(pt) for pt in PID_encryption]

        # PID_signature: [
        #   (commit_schnorr, commit_okamoto),  # 两个长度为环大小的承诺列表
        #   challenge[:-1],                    # 长度为环大小-1的挑战列表
        #   (response_schnorr, response_okamoto) # 两个长度为环大小的响应列表
        # ]
        commit_schnorr, commit_okamoto = PID_signature[0]
        challenge = PID_signature[1]
        response_schnorr, response_okamoto = PID_signature[2]

        commit_schnorr_str = [point_to_string(pt) for pt in commit_schnorr]
        commit_okamoto_str = [point_to_string(pt) for pt in commit_okamoto]

        # 将 challenge, response_schnorr, response_okamoto 中的 Integer 转为 int
        def to_int_list(lst):
            return [int(x) for x in lst]

        challenge_int = to_int_list(challenge)
        response_schnorr_int = to_int_list(response_schnorr)
        response_okamoto_int = to_int_list(response_okamoto)

        sig_dict = {
            "PID_encryption": enc_str,
            "PID_signature": [
                [commit_schnorr_str, commit_okamoto_str],
                challenge_int,
                [response_schnorr_int, response_okamoto_int]
            ]
        }
        return sig_dict

    @staticmethod
    def deserialize_signature(sig_dict, pp):
        """
        从序列化的dict恢复签名结果
        - F: 有限域
        - E: 椭圆曲线
        返回: (PID_encryption, PID_signature)
        """

        enc_str = sig_dict["PID_encryption"]
        PID_encryption = tuple(point_from_string(s, pp.F, pp.E) for s in enc_str)

        sig = sig_dict["PID_signature"]
        commit_schnorr_str, commit_okamoto_str = sig[0]
        challenge = sig[1]
        response_schnorr, response_okamoto = sig[2]

        commit_schnorr = [point_from_string(s, pp.F, pp.E) for s in commit_schnorr_str]
        commit_okamoto = [point_from_string(s, pp.F, pp.E) for s in commit_okamoto_str]

        # 将 int 转回 Integer
        def to_Integer_list(lst):
            return [Integer(x) for x in lst]

        challenge_int = to_Integer_list(challenge)
        response_schnorr_int = to_Integer_list(response_schnorr)
        response_okamoto_int = to_Integer_list(response_okamoto)

        PID_signature = [
            (commit_schnorr, commit_okamoto),
            challenge_int,
            (response_schnorr_int, response_okamoto_int)
        ]
        return (PID_encryption, PID_signature)

