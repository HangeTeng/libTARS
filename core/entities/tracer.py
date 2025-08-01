import json
import os
from core.crypto.public_params import load_full_public_params, point_from_string, point_to_string, PowerTable
from core.crypto.schnorr import schnorr_proof
from core.crypto.schnorr import batch_schnorr_verify
from sage.all import Integer, inverse_mod
from . import DEFAULT_PARAMS_PATH, DEFAULT_TRACER_SINGLE_KEY_FILE_FMT

class Tracer:
    def __init__(self, tracer_id, params_file=DEFAULT_PARAMS_PATH, key_file=None, load_key=True):
        """
        初始化追踪者，可指定公共参数文件和密钥文件。
        :param tracer_id: 追踪者ID
        :param params_file: 公共参数文件路径
        :param key_file: 追踪者密钥文件路径
        :param load_key: 是否加载密钥（可选）
        """
        self.tracer_id = tracer_id
        self.params_file = params_file
        if key_file is None:
            key_file = DEFAULT_TRACER_SINGLE_KEY_FILE_FMT.format(tracer_id)
        self.key_file = key_file

        # 加载公共参数
        self.pp = load_full_public_params(self.params_file)

        if load_key:
            self.load_key(self.key_file)
    
    def load_key(self, key_file=None):
        """从文件加载追踪者密钥"""
        key_file = key_file or self.key_file
        try:
            with open(key_file, 'r') as f:
                key_data = json.load(f)
            
            # 处理单个密钥文件或批量密钥文件
            if 'tracer_id' in key_data:
                # 单个密钥文件
                key_info = key_data
            else:
                # 批量密钥文件，需要根据tracer_id查找
                if self.tracer_id not in key_data:
                    raise ValueError(f"Tracer {self.tracer_id} not found in key file")
                key_info = key_data[self.tracer_id]
            
            self.x_i = key_info['x_i']
            self.pub_share = point_from_string(key_info['pub_share'], self.pp.F, self.pp.E)
            self.d_share = key_info['d_share']
            self.proof = None
            
        except FileNotFoundError:
            raise FileNotFoundError(f"Tracer key file {key_file} not found. Please generate keys using KGC first.")
        except KeyError as e:
            raise ValueError(f"Invalid key file format: missing {e}")

    def partial_decrypt(self, signature):
        """
        输入签名信息生成部分解密
        :param signature_info: 签名信息，可以是序列化的dict或(C1, C2, T)元组
        :return: (s_i, proof) 部分解密结果和证明
        """
        PID_encryption, PID_signature = signature
        C1 = PID_encryption[0]
        # 创建C1的预计算表
        C1_table = PowerTable(C1)
        
        # 部分解密
        s_share = C1_table.multiply(self.d_share)
        proof = schnorr_proof(self.d_share, self.pp)
        
        return (self.x_i, s_share, proof)

    @classmethod
    def serialize_decrypt_result(cls, partial_decrypt_result):
        """
        序列化部分解密结果
        :param x_i: 坐标x_i
        :param s_share: 部分解密结果点
        :param proof: Schnorr证明 (T, s)
        :return: 序列化的dict
        """
        x_i, s_share, proof = partial_decrypt_result
        T, s = proof
        return {
            "x_i": x_i,
            "s_share": point_to_string(s_share),
            "proof": (point_to_string(T), int(s))
        }

    @classmethod
    def deserialize_decrypt_result(cls, serialized_result, pp):
        """
        反序列化部分解密结果
        :param serialized_result: 序列化的解密结果dict
        :param pp: 公共参数对象
        :return: (x_i, s_share, proof)
        """
        x_i = serialized_result["x_i"]
        s_share = point_from_string(serialized_result["s_share"], pp.F, pp.E)
        proof = (point_from_string(serialized_result["proof"][0], pp.F, pp.E), Integer(serialized_result["proof"][1]))
        return (x_i, s_share, proof)

    @classmethod    
    def combine(cls, D_list, partial_decrypt_results, signature, pp):
        """
        组合多个追踪者的份额进行解密
        :param shares: [(s_i, x_i), ...] 部分解密结果列表
        :param signature_info: 签名信息，可以是序列化的dict或(C1, C2, T)元组
        :param pp: 公共参数对象（如果为None，将从默认路径加载）
        :return: 解密后的PID
        """
        PID_encryption, PID_signature = signature
        C1, C2, T = PID_encryption
        C2_table = PowerTable(C2)
        
        # 组合份额进行解密
        x_list, s_points, proofs = zip(*partial_decrypt_results)
        
        # 使用schnorr.py中的batch_schnorr_verify进行批量验证
        assert batch_schnorr_verify(D_list, proofs, pp), "分组解密证明无效"
        
        # 计算拉格朗日插值系数
        modulus = int(pp.ModRing.order())
        inverses = {}
        for i in range(len(partial_decrypt_results)):
            denominator = 1
            for j in range(len(partial_decrypt_results)):
                if i != j:
                    denominator *= (x_list[i] - x_list[j]) % modulus
            inverses[i] = inverse_mod(denominator, modulus)
        
        # 计算最终结果
        result_point = pp.E(0)
        for i in range(len(partial_decrypt_results)):
            numerator = 1
            for j in range(len(partial_decrypt_results)):
                if i != j:
                    numerator = (-x_list[j]) % modulus
            lambda_i = (numerator * inverses[i]) % modulus
            result_point += s_points[i] * Integer(lambda_i)
        
        # 计算PID
        PID = C2 - result_point
        return PID
