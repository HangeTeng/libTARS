# libTARS 配置和密钥管理

## 概述

libTARS 是一个基于椭圆曲线密码学的可追踪匿名环签名系统，包含三个主要实体：
- **KGC (Key Generation Center)**: 密钥生成中心，负责生成系统参数和所有实体的密钥
- **User**: 用户实体，可以生成匿名环签名
- **Tracer**: 追踪者实体，可以协作解密用户身份

## 配置参数结构

### 1. 基本参数 (`core/config/params.json`)

```json
{
  "curve": {
    "q": 15028799613985034465755506450771565229282832217860390155996483840017,
    "a": 1871224163624666631860092489128939059944978347142292177323825642096,
    "b": 9795501723343380547144152006776653149306466138012730640114125605701,
    "n": 15028799613985034465755506450771561352583254744125520639296541195021,
    "r": 15028799613985034465755506450771561352583254744125520639296541195021
  },
  "protocol": {
    "k": 6,
    "t": 5,
    "n_tracers": 10
  }
}
```

**参数说明**:
- `curve`: 椭圆曲线参数
  - `q`: 有限域的阶
  - `a`, `b`: 椭圆曲线方程 y² = x³ + ax + b 的系数
  - `n`: 椭圆曲线群的阶
  - `r`: 配对群的阶
- `protocol`: 协议参数
  - `k`: 有限域扩展次数
  - `t`: Shamir秘密共享的阈值
  - `n_tracers`: 追踪者总数

### 2. 公开参数 (`core/config/public_params.json`)

由KGC生成，包含：
- 椭圆曲线生成元 `g1`, `g2`
- 系统公钥 `Q`
- 基本参数（曲线参数、协议参数）

## 密钥管理

### KGC 密钥生成流程

1. **系统初始化**:
   ```python
   kgc = KGC()  # 自动加载 params.json
   ```

2. **生成系统参数**:
   - 设置椭圆曲线
   - 生成主密钥 `s`
   - 生成 Shamir 秘密共享份额
   - 计算系统公钥 `Q = s * g1`

3. **生成用户密钥**:
   ```python
   user_key = kgc.generate_user_key("user_id")
   # 返回: {sk, pk, pid, event_hash}
   ```

4. **生成追踪者密钥**:
   ```python
   tracer_key = kgc.generate_tracer_key(tracer_id)
   # 返回: {x_i, d_share}
   ```

### 密钥文件结构

#### 用户密钥文件
```json
{
  "user_id": "alice",
  "sk": 123456789,
  "pk": "(x_coord, y_coord)",
  "pid": "(x_coord, y_coord)",
  "event_hash": 987654321
}
```

#### 追踪者密钥文件
```json
{
  "tracer_id": 1,
  "x_i": 1,
  "d_share": 123456789
}
```

#### 主密钥文件（仅KGC访问）
```json
{
  "master_key_s": 123456789,
  "poly_coeffs": [s, a1, a2, ...],
  "tracer_shares": [[1, share1], [2, share2], ...]
}
```

## 实体初始化

### User 初始化
```python
user = User("user_id", "path/to/user_keys.json")
# 自动加载密钥并注册到环签名环
```

### Tracer 初始化
```python
tracer = Tracer(tracer_id, "path/to/tracer_keys.json")
# 自动加载秘密份额
```

## 参数共享机制

### 1. 配置参数加载
- **KGC**: 直接从 `params.json` 加载基本参数
- **User/Tracer**: 通过 `public_params.py` 模块访问公开参数

### 2. 全局参数实例
```python
from core.crypto.public_params import pp, g1_table, Q_table, Ring, Ring_table
```

### 3. 参数更新流程
1. KGC 修改 `params.json`
2. 重新初始化 KGC 生成新的系统参数
3. 保存新的 `public_params.json`
4. User 和 Tracer 自动使用新的公开参数

## 安全考虑

1. **主密钥保护**: 主密钥文件应严格限制访问权限
2. **密钥分发**: 用户和追踪者密钥应通过安全通道分发
3. **参数验证**: 所有实体应验证加载的参数完整性
4. **密钥轮换**: 定期更新系统参数和密钥

## 使用示例

运行系统演示：
```bash
python examples/system_demo.py
```

这将展示完整的密钥生成、实体初始化和签名追踪流程。 