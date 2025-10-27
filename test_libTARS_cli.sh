#!/bin/bash

# 1. 设置环境变量，确保脚本在 libTARS_cli.py 所在目录运行
cd "$(dirname "$0")"

echo "==== 1. 测试 setup 生成主密钥和公钥 ===="
python libTARS_cli.py kgc setup -p config/params.json -k config/kgc/key.json

echo "==== 2. 测试 tracerkeygen 生成所有追踪者密钥份额 ===="
python libTARS_cli.py kgc tracerkeygen -p config/params.json -k config/kgc/key.json -o config/tracer/tracer_keys.json -sf "config/tracer/tracer_{}_key.json" -spf "config/tracer/tracer_{}_pub.json"

# for uid in 1001; do
#     # python libTARS_cli.py user keygen $uid 
#     # # 补充签名
#     # # 创建待签名消息文件
#     # mkdir -p temp
#     # echo "This is a test message for ring signature." > temp/test_message.txt

#     # 用用户1001对消息进行环签名，环只包含自己
#     python libTARS_cli.py user sign $uid temp/test_message.txt $uid -p config/params.json -d config/user -o temp/test_signature_${uid}.json

#     # 验证环签名
#     python libTARS_cli.py user verify temp/test_message.txt -p config/params.json -d config/user -i temp/test_signature_${uid}.json
# done

echo "==== 3. 生成3个用户密钥 ===="
for uid in 1001 1002 1003 1004 1005 1006 1007 1008 1009 1010; do
    python libTARS_cli.py user keygen $uid -p config/params.json -d config/user -k config/user/user_${uid}_key.json -pk config/user/user_${uid}_pub.json
done

echo "==== 4. 创建待签名消息文件 ===="
mkdir -p temp
echo "This is a test message for ring signature." > temp/test_message.txt

echo "==== 5. 用用户1001对消息进行环签名 ===="
python libTARS_cli.py user sign 1001 temp/test_message.txt 1001,1002,1003,1004,1005,1006,1007,1008,1009,1010 -p config/params.json -d config/user -o temp/test_signature.json

echo "==== 6. 验证环签名 ===="
python libTARS_cli.py user verify temp/test_message.txt -p config/params.json -d config/user -i temp/test_signature.json

echo "==== 7. 用追踪者对签名进行部分解密 ===="
for tid in 1 2; do
    python libTARS_cli.py tracer partial_decrypt $tid -p config/params.json -k config/tracer/tracer_${tid}_key.json -i temp/test_signature.json -o temp/test_partial_decrypt_${tid}.json
done

echo "==== 8. 用追踪者恢复PID ===="
python libTARS_cli.py tracer recover -p config/params.json -i temp/test_signature.json -s temp/test_partial_decrypt_1.json,temp/test_partial_decrypt_2.json -o temp/test_pid.txt