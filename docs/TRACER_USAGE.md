# Tracer 类使用指南

## 概述

修改后的 `Tracer` 类提供了完整的追踪者功能，支持按ID实例化、输入签名信息生成部分解密、序列化和反序列化解密结果，以及组合恢复多个份额。

## 主要功能

### 1. 按ID实例化

```python
from core.entities.tracer import Tracer

# 实例化ID为0的追踪者
tracer = Tracer(0)

# 指定自定义参数文件和密钥文件
tracer = Tracer(
    tracer_id=1,
    params_file="path/to/params.json",
    key_file="path/to/tracer_key.json",
    load_key=True  # 可选，默认为True
)
```

### 2. 输入签名信息生成部分解密

```python
# 方法1：使用序列化的签名信息
serialized_signature = {
    "PID_encryption": ["(x1,y1)", "(x2,y2)", "(x3,y3)"],
    "PID_signature": [...]
}
s_i, proof = tracer.partial_decrypt(serialized_signature)

# 方法2：使用原始的签名元组
PID_encryption = (C1, C2, T)
s_i, proof = tracer.partial_decrypt(PID_encryption)
```

### 3. 序列化和反序列化解密结果

```python
# 序列化解密结果
serialized_result = tracer.serialize_decrypt_result(s_i, proof)
# 结果格式：
# {
#     "tracer_id": 0,
#     "x_i": 0,
#     "s_i": "(x,y)",
#     "proof": {...}
# }

# 反序列化解密结果
s_i, x_i, proof = Tracer.deserialize_decrypt_result(
    serialized_result, tracer.F, tracer.E
)
```

### 4. 组合恢复多个份额

```python
# 方法1：使用原始份额列表
shares = [(s_i1, x_i1), (s_i2, x_i2), ...]
recovered_pid = Tracer.combine(shares, signature_info)

# 方法2：使用序列化的份额列表
serialized_shares = [serialized_result1, serialized_result2, ...]
recovered_pid = Tracer.combine_from_serialized(
    serialized_shares, signature_info, F, E
)
```

### 5. 便捷方法

```python
# 一步完成：输入签名信息，返回序列化的解密结果
serialized_result = tracer.process_signature(signature_info)
```

## 完整使用示例

```python
from core.entities.tracer import Tracer
from core.entities.user import User

# 1. 创建用户并生成签名
user = User("1001")
message = "important message"
ring_user_ids = ["1001", "1002", "1003"]
PID_encryption, PID_signature, C2_table, ring_user_ids = user.sign(
    message, ring_user_ids
)
serialized_signature = User.serialize_signature(PID_encryption, PID_signature)

# 2. 创建多个追踪者
tracers = [Tracer(i) for i in range(3)]  # 创建3个追踪者

# 3. 每个追踪者进行部分解密
serialized_results = []
for tracer in tracers:
    result = tracer.process_signature(serialized_signature)
    serialized_results.append(result)

# 4. 组合恢复PID
recovered_pid = Tracer.combine_from_serialized(
    serialized_results, serialized_signature, tracers[0].F, tracers[0].E
)

print(f"恢复的PID: {recovered_pid}")
```

## 错误处理

```python
try:
    tracer = Tracer(0)
    result = tracer.partial_decrypt(signature_info)
except FileNotFoundError as e:
    print(f"密钥文件未找到: {e}")
except ValueError as e:
    print(f"参数错误: {e}")
except Exception as e:
    print(f"其他错误: {e}")
```

## 注意事项

1. **密钥文件路径**：默认密钥文件路径为 `config/tracer/tracer_keys_{id}_key.json`
2. **参数文件路径**：默认参数文件路径为 `config/params.json`
3. **签名信息格式**：支持序列化的dict格式和原始的(C1, C2, T)元组格式
4. **序列化格式**：所有椭圆曲线点都使用字符串格式 `"(x,y)"` 进行序列化
5. **组合恢复**：需要至少 `t` 个追踪者的份额才能成功恢复PID

## API 参考

### Tracer 类方法

- `__init__(tracer_id, params_file=None, key_file=None, load_key=True)`
- `load_key(key_file=None)`
- `partial_decrypt(signature_info)`
- `serialize_decrypt_result(s_i, proof)`
- `process_signature(signature_info)`

### 类方法

- `Tracer.deserialize_decrypt_result(serialized_result, F, E)`
- `Tracer.combine(shares, signature_info, pp=None)`
- `Tracer.combine_from_serialized(serialized_shares, signature_info, F, E)` 