#!/usr/bin/env python3
"""
测试修改后的Tracer类功能（需要两个tracer的份额）
"""

import json
from core.entities.tracer import Tracer
from core.entities.user import User
from core.crypto.public_params import load_full_public_params, point_to_string

def test_tracer_functionality():
    """测试Tracer类的各项功能（需要两个tracer的份额）"""
    print("=== 测试Tracer类功能（两个tracer份额） ===")

    # 1. 测试按ID实例化
    print("\n1. 测试按ID实例化...")
    try:
        tracer1 = Tracer(1)
        tracer2 = Tracer(2)
        print(f"✓ 成功实例化追踪者1 ID: {tracer1.tracer_id}")
        print(f"  x_i: {tracer1.x_i}")
        print(f"  d_share: {tracer1.d_share}")
        print(f"✓ 成功实例化追踪者2 ID: {tracer2.tracer_id}")
        print(f"  x_i: {tracer2.x_i}")
        print(f"  d_share: {tracer2.d_share}")
    except Exception as e:
        print(f"✗ 实例化失败: {e}")
        return

    # 2. 测试加载公共参数
    print("\n2. 测试公共参数加载...")
    try:
        pp = load_full_public_params("config/params.json")
        print(f"✓ 成功加载公共参数")
        print(f"  g1: {point_to_string(pp.g1)}")
        print(f"  g2: {point_to_string(pp.g2)}")
        print(f"  Q: {point_to_string(pp.Q)}")
    except Exception as e:
        print(f"✗ 加载公共参数失败: {e}")
        return

    # 3. 测试用户签名生成
    print("\n3. 测试用户签名生成...")
    try:
        user = User("1001")
        message = "test message"
        ring_user_ids = ["1001", "1002", "1003"]
        signature = user.sign(message, ring_user_ids)
        serialized_signature = User.serialize_signature(signature)
        print(f"✓ 成功生成签名")
        print(f"  PID_encryption: {signature[0]}")
        print(f"  PID_signature: {signature[1]}")
        print(f"  序列化签名: {json.dumps(serialized_signature, indent=2)[:200]}...")
    except Exception as e:
        print(f"✗ 签名生成失败: {e}")
        return

    # 4. 测试部分解密（两个tracer）
    print("\n4. 测试部分解密（两个tracer）...")
    try:
        # 反序列化签名
        partial1 = tracer1.partial_decrypt(signature)
        partial2 = tracer2.partial_decrypt(signature)
        print(f"✓ 成功进行部分解密")
        print(f"  tracer1 partial: {partial1}")
        print(f"  tracer2 partial: {partial2}")

        # 序列化解密结果
        serialized_result1 = Tracer.serialize_decrypt_result(partial1)
        serialized_result2 = Tracer.serialize_decrypt_result(partial2)
        print(f"✓ 成功序列化解密结果")
        print(f"  tracer1 序列化结果: {json.dumps(serialized_result1, indent=2)}")
        print(f"  tracer2 序列化结果: {json.dumps(serialized_result2, indent=2)}")
    except Exception as e:
        print(f"✗ 部分解密失败: {e}")
        return

    # 5. 测试反序列化
    print("\n5. 测试反序列化...")
    try:
        des1 = Tracer.deserialize_decrypt_result(serialized_result1, tracer1.pp)
        des2 = Tracer.deserialize_decrypt_result(serialized_result2, tracer2.pp)
        print(f"✓ 成功反序列化解密结果")
        print(f"  tracer1: {des1}")
        print(f"  tracer2: {des2}")
        # 验证反序列化结果正确性
        if (partial1[0] == des1[0] and partial2[0] == des2[0]):
            print(f"✓ 反序列化结果验证正确")
        else:
            print(f"✗ 反序列化结果验证失败")
    except Exception as e:
        print(f"✗ 反序列化失败: {e}")
        return

    # 6. 测试组合恢复（需要两个tracer的份额）
    print("\n6. 测试组合恢复（需要两个tracer的份额）...")
    try:
        D_list = [tracer1.pub_share, tracer2.pub_share]
        partials = [partial1, partial2]
        recovered_pid = Tracer.combine(D_list, partials, signature, tracer1.pp)
        print(f"✓ 成功组合恢复PID")
        print(f"  恢复的PID: {recovered_pid}")
    except Exception as e:
        print(f"✗ 组合恢复失败: {e}")
        return

    print("\n=== 所有测试完成 ===")

if __name__ == "__main__":
    test_tracer_functionality()