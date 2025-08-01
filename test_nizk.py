# INSERT_YOUR_CODE

# 仅测试 core/crypto/nizk.py 的 ring_proof 和 verify_ring_proof
# 只加载必要的参数和点，不依赖完整的 CLI 或 User 类

import os
import json
from sage.all import Integer
from core.entities.user import User
from core.crypto.public_params import load_full_public_params, point_from_string, PowerTable
from core.crypto.nizk import ring_proof, verify_ring_proof


def load_ring_simple(user_ids, user_dir, pp):
    """
    加载环成员的pid（公钥）和PowerTable
    返回: Ring, Ring_table, id2index
    """
    user_ids = [str(uid) for uid in user_ids]
    Ring = []
    Ring_table = []
    id2index = {}
    for idx, uid in enumerate(user_ids):
        key_file = os.path.join(user_dir, f"user_{uid}_public_key.json")
        with open(key_file, 'r') as f:
            key_data = json.load(f)
        if 'user_id' in key_data:
            key_info = key_data
        else:
            key_info = key_data[uid]
        pk = point_from_string(key_info['pk'], pp.F, pp.E)
        print(f"pk: {pk}")
        pid = point_from_string(key_info['pid'], pp.F, pp.E)
        Ring.append(pp.R(pk, pid))
        Ring_table.append(PowerTable(pid))
        id2index[uid] = idx + 1
    return Ring, Ring_table, id2index

def test_ring_proof_and_verify():
    # 配置参数
    config_dir = os.path.join(os.path.dirname(__file__), 'config')
    params_file = os.path.join(config_dir, 'params.json')
    user_dir = os.path.join(config_dir, 'user')
    # 创建一个包含3个相同用户的环来测试
    user_ids = ['1001']  # 使用同一个用户3次来创建环
    message = "This is a test message for ring signature."
    event = "default"

    # 加载系统参数
    pp = load_full_public_params(params_file)

    g1_table = PowerTable(pp.g1)
    Q_table = PowerTable(pp.Q)

    # 加载环
    Ring, Ring_table, id2index = load_ring_simple(user_ids, user_dir, pp)
    print(f"Ring: {Ring}")
    print(f"Ring_table: {Ring_table}")
    print(f"id2index: {id2index}")

    # 选择签名者
    signer_id = '1001'
    signer_idx = id2index[signer_id]   # 这会是0，因为第一个1001的索引是0
    print(f"signer_idx: {signer_idx}")
    # 加载签名者私钥
    key_file = os.path.join(user_dir, f"user_{signer_id}_key.json")
    with open(key_file, 'r') as f:
        key_data = json.load(f)
    sk = Integer(key_data['sk'])
    pid = point_from_string(key_data['pid'], pp.F, pp.E)

    # event hash
    import hashlib
    event_bytes = event.encode('utf-8')
    event_hash = int(hashlib.sha256(event_bytes).hexdigest(), 16)

    # 生成签名加密
    k = 1 #pp.rand_int()
    k_int = Integer(k)
    C1 = g1_table.multiply(k_int)
    C2 = pid + Q_table.multiply(k_int)
    T = g1_table.multiply(Integer(event_hash))
    PID_encryption = (C1, C2, T)
    C2_table = PowerTable(C2, window_size=2)

    
    # 生成环签名证明
    # ring_proof的输入
    print(f"signer_idx: {signer_idx}")
    print(f"sk: {sk}")
    print(f"k_int: {k_int}")
    print(f"C2: {C2}")
    print(f"message: {message}")
    print(f"C2_table: {C2_table}")
    print(f"Ring: {Ring}")
    print(f"Ring_table: {Ring_table}")
    print(f"pp: {pp}")
    print(f"g1: {pp.g1}")
    print(f"Q: {pp.Q}")
    print(f"g1_table: {g1_table}")
    print(f"Q_table: {Q_table}")
    # ring_proof的输出
    proof = ring_proof(
        signer_idx, sk, k_int, C2, message, C2_table, Ring, Ring_table,
        pp, g1_table, Q_table
    )
    print(f"proof: {proof}")
    print(User.serialize_signature(PID_encryption, proof))
    # 验证
    print("="*100)
    print(f"C2: {C2}")
    print(f"proof: {proof}")
    print(f"message: {message}")
    print(f"Ring: {Ring}")
    print(f"pp: {pp}")
    print(f"g1: {pp.g1}")
    print(f"Q: {pp.Q}")
    print(f"E: {pp.E}")
    result = verify_ring_proof(
        C2_table, proof, message, Ring, Ring_table,
        pp, g1_table, Q_table, pp.E
    )
    print("Ring proof verify result:", result)
    assert result is True

if __name__ == "__main__":
    test_ring_proof_and_verify()
