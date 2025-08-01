import argparse
import os
import json
from core.entities.kgc import KGC
from core.entities.user import User
from core.entities.tracer import Tracer
from core.crypto.public_params import point_to_string, point_from_string  # 新增：点转化函数
from core.entities import DEFAULT_PARAMS_PATH, DEFAULT_KGC_KEY_PATH, DEFAULT_TRACER_KEYS_FILE, DEFAULT_TRACER_SINGLE_KEY_FILE_FMT, DEFAULT_TRACER_SINGLE_PUBLIC_KEY_FILE_FMT, DEFAULT_USER_KEYS_DIR, DEFAULT_USER_SINGLE_KEY_FILE_FMT, DEFAULT_USER_SINGLE_PUBLIC_KEY_FILE_FMT

# 全局语言参数: "zh"（中文）或 "en"（英文）
LANG = "zh"

CONFIG_DIR = "config"
KGC_DIR = os.path.join(CONFIG_DIR, "kgc")
TRACER_DIR = os.path.join(CONFIG_DIR, "tracer")

def t(msg_zh, msg_en):
    """根据全局LANG返回中英文消息"""
    return msg_zh if LANG == "zh" else msg_en

def ensure_dirs():
    for d in [KGC_DIR, TRACER_DIR]:
        os.makedirs(d, exist_ok=True)

# ----------- KGC 命令实现 -----------
def kgc_setup(args):
    """
    生成系统主密钥s和公钥，并写入params.json和key.json
    """
    ensure_dirs()
    params_path = args.params or DEFAULT_PARAMS_PATH
    key_path = args.key or DEFAULT_KGC_KEY_PATH
    # 仅当 key.json 已存在时才警告
    if os.path.exists(key_path):
        print(t(
            "警告：此操作将生成并覆盖现有系统公钥和主密钥。",
            "WARNING: This operation will generate and overwrite the existing system public key and master key."
        ))
        print(t(    
            "如果继续，原有的主密钥和公钥将被新值替换，所有依赖于旧公钥的user和tracer密钥将失效。",
            "If you continue, the original master key and public key will be replaced, and all user and tracer keys depending on the old public key will become invalid."
        ))
        # confirm = input(t("是否继续？(y/N): ", "Continue? (y/N): ")).strip().lower()
        # if confirm != "y":
        #     print(t("操作已取消。", "Operation cancelled."))
        #     return
    # 直接调用KGC，自动生成主密钥和Q，并写入params.json和key.json
    kgc_inst = KGC(params_path=params_path, key_path=key_path, load_key=False)
    kgc_inst.generate_master_key(save_key=True, save_public_params=True)
    print(t(
        f"系统主密钥和系统公钥已生成。\n- key.json: {key_path}\n- params.json: {params_path}",
        f"System master key and system public key have been generated.\n- key.json: {key_path}\n- params.json: {params_path}"
    ))
    print(t(
        "新参数生成，注意重新发布和更新user和tracer密钥。",
        "New parameters generated. Please remember to redistribute and update user and tracer keys."
    ))

def kgc_tracerkeygen(args):
    """
    生成所有追踪者Shamir密钥份额，并保存到指定文件
    """
    ensure_dirs()
    params_path = args.params or DEFAULT_PARAMS_PATH
    key_path = args.key or DEFAULT_KGC_KEY_PATH
    out_path = args.output or DEFAULT_TRACER_KEYS_FILE
    # print(args)
    single_key_file_fmt = args.single_key_file_fmt or DEFAULT_TRACER_SINGLE_KEY_FILE_FMT
    single_public_key_file_fmt = args.single_public_key_file_fmt or DEFAULT_TRACER_SINGLE_PUBLIC_KEY_FILE_FMT
    kgc_inst = KGC(params_path=params_path, key_path=key_path, load_key=True)
    kgc_inst.generate_tracer_keys(save_all=True, save_single=True, tracer_keys_path=out_path, single_key_file_fmt=single_key_file_fmt, single_public_key_file_fmt=single_public_key_file_fmt)
    print(t(
        f"所有追踪者密钥已保存到 {out_path}，单个追踪者密钥已保存到 {single_key_file_fmt.format('trace_id')} 和 {single_public_key_file_fmt.format('trace_id')}",
        f"All tracer keys have been saved to {out_path}, single tracer keys have been saved to {single_key_file_fmt.format('trace_id')} and {single_public_key_file_fmt.format('trace_id')}"
    ))

# ----------- User 命令实现 -----------
def user_keygen(args):
    """
    生成用户密钥对并保存到文件
    """
    user_id = args.user_id
    params_file = args.params or DEFAULT_PARAMS_PATH
    user_dir = args.user_dir or DEFAULT_USER_KEYS_DIR
    key_file = args.key or os.path.join(user_dir, DEFAULT_USER_SINGLE_KEY_FILE_FMT.format(user_id))
    public_key_file = args.public_key or os.path.join(user_dir, DEFAULT_USER_SINGLE_PUBLIC_KEY_FILE_FMT.format(user_id))
    os.makedirs(user_dir, exist_ok=True)
    # 检查密钥文件是否已存在，警告用户会覆盖
    if os.path.exists(key_file):
        print(t(
            f"警告：用户密钥文件 {key_file} 和公钥文件 {public_key_file} 已存在，将被覆盖。",
            f"WARNING: User key file {key_file} and public key file {public_key_file} already exist and will be overwritten."
        ))
        # confirm = input(t("是否继续？(y/N): ", "Continue? (y/N): ")).strip().lower()
        # if confirm != "y":
        #     print(t("操作已取消。", "Operation cancelled."))
        #     return
    user = User(user_id, params_file=params_file, key_file=key_file, load_key=False)
    user.generate_key(save_key=True)
    print(t(
        f"用户 {user_id} 密钥已生成并保存到 {key_file} 和 {public_key_file}",
        f"User {user_id} key generated and saved to {key_file} and {public_key_file}"
    ))

def user_sign(args):
    """
    用户对消息进行环签名
    支持 -m/--message 可以是文件名或字符串，-L/--ring 可以是文件名或逗号分隔字符串
    """
    user_id = args.user_id
    params_file = args.params or DEFAULT_PARAMS_PATH
    user_dir = args.user_dir or DEFAULT_USER_KEYS_DIR
    key_file = args.key or os.path.join(user_dir, DEFAULT_USER_SINGLE_KEY_FILE_FMT.format(user_id)) # 用户密钥文件
    event = args.event or "default"
    out_file = args.output

    # 处理消息
    message = None
    if hasattr(args, "message") and args.message:
        msg_arg = args.message
        # 如果是文件且存在，则读取文件内容
        if os.path.isfile(msg_arg):
            with open(msg_arg, "r", encoding="utf-8") as f:
                message = f.read()
        else:
            message = msg_arg
    else:
        print(t("未指定消息且默认消息文件不存在。", "No message specified and default message file does not exist."))
        return

    # 处理环
    ring_user_ids = None
    if hasattr(args, "ring") and args.ring:
        ring_arg = args.ring
        # 如果是单个参数且为文件名且存在，则读取文件内容
        if isinstance(ring_arg, list) and len(ring_arg) == 1 and os.path.isfile(ring_arg[0]):
            with open(ring_arg[0], "r", encoding="utf-8") as f:
                ring_content = f.read().strip()
                # 支持逗号或空格分隔
                if "," in ring_content:
                    ring_user_ids = [x.strip() for x in ring_content.split(",") if x.strip()]
                else:
                    ring_user_ids = [x.strip() for x in ring_content.split() if x.strip()]
        elif isinstance(ring_arg, list) and len(ring_arg) == 1 and "," in ring_arg[0]:
            # 逗号分隔字符串
            ring_user_ids = [x.strip() for x in ring_arg[0].split(",") if x.strip()]
        else:
            # 直接传递的用户ID列表
            ring_user_ids = [str(x) for x in ring_arg]
    else:
        # 默认环文件路径
        default_ring_path = os.path.join("temp", "test_ring.txt")
        if os.path.isfile(default_ring_path):
            with open(default_ring_path, "r", encoding="utf-8") as f:
                ring_content = f.read().strip()
                if "," in ring_content:
                    ring_user_ids = [x.strip() for x in ring_content.split(",") if x.strip()]
                else:
                    ring_user_ids = [x.strip() for x in ring_content.split() if x.strip()]
        else:
            print(t("未指定环且默认环文件不存在。", "No ring specified and default ring file does not exist."))
            return

    user = User(user_id, params_file=params_file, key_file=key_file)
    signature = user.sign(message, ring_user_ids, event=event)

    # 使用User类的序列化方法
    result = User.serialize_signature(signature)
    result.update({
        "ring_user_ids": ring_user_ids,
        "event": event
    })

    if out_file:
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(t(
            f"签名结果已保存到 {out_file}",
            f"Signature result saved to {out_file}"
        ))
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))

def user_verify(args):
    """
    验证用户环签名（无需加载用户密钥）
    """
    params_file = args.params or DEFAULT_PARAMS_PATH
    user_dir = args.user_dir or DEFAULT_USER_KEYS_DIR
    input_file = args.input
    if not input_file or not os.path.exists(input_file):
        print(t(f"签名输入文件 {input_file} 不存在。", f"Signature input file {input_file} does not exist."))
        return

    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    # 兼容不同字段名
    ring_user_ids = data.get("ring_user_ids")
    event = data.get("event", "default")
    # 处理消息
    message = None
    if hasattr(args, "message") and args.message:
        msg_arg = args.message
        # 如果是文件且存在，则读取文件内容
        if os.path.isfile(msg_arg):
            with open(msg_arg, "r", encoding="utf-8") as f:
                message = f.read()
        else:
            message = msg_arg
    else:
        print(t("未指定消息且默认消息文件不存在。", "No message specified and default message file does not exist."))
        return

    # user.py的verify接口: verify(self, message, PID_encryption, PID_signature, ring_user_ids, event="default")
    # 只需实例化User，不需要密钥
    user = User("0", params_file=params_file, load_key=False)  # user_id随便填，不加载密钥
    
    try:
        sig_dict = {
            "PID_encryption": data["PID_encryption"],
            "PID_signature": data["PID_signature"]
        }
        signature = User.deserialize_signature(sig_dict, user.pp)
    except Exception as e:
        print(t(f"签名反序列化失败: {e}", f"Failed to deserialize signature: {e}"))
        return


    try:
        valid = user.verify(message, signature, ring_user_ids, event, user_dir)
    except Exception as e:
        print(t(f"验证过程中发生错误: {e}", f"Error during verification: {e}"))
        return

    if valid:
        print(t("签名验证通过。", "Signature verification PASSED."))
    else:
        print(t("签名验证失败。", "Signature verification FAILED."))

# ----------- Tracer 命令实现 -----------
def tracer_partial_decrypt(args):
    """
    追踪者对签名进行部分解密
    输入: 
        -t/--tracer-id: 追踪者ID
        -i/--input: 签名输入文件 (包含PID_encryption, PID_signature)
        -k/--key: 追踪者密钥文件
        -p/--params: 公共参数文件
        -o/--output: 输出部分解密结果文件
    """
    from core.entities.tracer import Tracer

    tracer_id = args.tracer_id
    input_file = args.input
    key_file = args.key
    params_file = args.params
    output_file = args.output

    if not input_file or not os.path.exists(input_file):
        print(t(f"签名输入文件 {input_file} 不存在。", f"Signature input file {input_file} does not exist."))
        return

    # 读取签名文件
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    try:
        sig_dict = {
            "PID_encryption": data["PID_encryption"],
            "PID_signature": data["PID_signature"]
        }
    except Exception as e:
        print(t(f"签名文件格式错误: {e}", f"Invalid signature file format: {e}"))
        return

    # 初始化Tracer
    try:
        tracer = Tracer(tracer_id, params_file=params_file, key_file=key_file, load_key=True)
    except Exception as e:
        print(t(f"Tracer初始化失败: {e}", f"Failed to initialize Tracer: {e}"))
        return

    # 反序列化签名
    try:
        # 参考 test_tracer.py, 使用User.deserialize_signature
        from core.entities.user import User
        signature = User.deserialize_signature(sig_dict, tracer.pp)
    except Exception as e:
        print(t(f"签名反序列化失败: {e}", f"Failed to deserialize signature: {e}"))
        return

    # 进行部分解密
    try:
        partial_result = tracer.partial_decrypt(signature)
        serialized_result = Tracer.serialize_decrypt_result(partial_result)
    except Exception as e:
        print(t(f"部分解密失败: {e}", f"Partial decryption failed: {e}"))
        return

    # 输出到文件，并附加tracer_id
    output_data = dict(serialized_result)
    output_data["tracer_id"] = tracer_id
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)
        print(t(f"部分解密结果已保存到 {output_file}", f"Partial decryption result saved to {output_file}"))
    else:
        print(json.dumps(output_data, indent=2))


def tracer_combine(args):
    """
    追踪者组合部分解密结果恢复PID
    输入:
        -i/--input: 签名输入文件 (包含PID_encryption, PID_signature)
        -t/--tracer-ids: 追踪者ID列表 (多个, 逗号分隔或多次-t)
        -s/--shares: 部分解密结果文件列表 (多个, 逗号分隔或多次-s)
        -p/--params: 公共参数文件
    """
    from core.entities.tracer import Tracer

    input_file = args.input
    params_file = args.params

    # 支持 shares 既可以是列表，也可以是逗号分隔的字符串
    shares_files = args.shares
    if isinstance(shares_files, str):
        # 兼容逗号分隔
        shares_files = [f.strip() for f in shares_files.split(",") if f.strip()]
    elif isinstance(shares_files, list):
        # 支持多次-s/--shares
        # 展开可能的逗号分隔
        expanded = []
        for item in shares_files:
            if isinstance(item, str) and "," in item:
                expanded.extend([f.strip() for f in item.split(",") if f.strip()])
            else:
                expanded.append(item)
        shares_files = expanded
    else:
        shares_files = []

    if not input_file or not os.path.exists(input_file):
        print(t(f"签名输入文件 {input_file} 不存在。", f"Signature input file {input_file} does not exist."))
        return
    if not shares_files or len(shares_files) == 0:
        print(t("必须指定至少一个部分解密结果文件 (--shares)", "At least one partial decryption result file (--shares) is required"))
        return

    # 读取签名文件
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    try:
        sig_dict = {
            "PID_encryption": data["PID_encryption"],
            "PID_signature": data["PID_signature"]
        }
    except Exception as e:
        print(t(f"签名文件格式错误: {e}", f"Invalid signature file format: {e}"))
        return

    # 加载公共参数
    from core.crypto.public_params import load_full_public_params, point_from_string
    pp = load_full_public_params(params_file)

    # 反序列化签名
    try:
        from core.entities.user import User
        signature = User.deserialize_signature(sig_dict, pp)
    except Exception as e:
        print(t(f"签名反序列化失败: {e}", f"Failed to deserialize signature: {e}"))
        return

    # 读取所有部分解密结果
    partial_results = []
    D_list = []
    for share_file in shares_files:
        if not os.path.exists(share_file):
            print(t(f"部分解密结果文件 {share_file} 不存在。", f"Partial decryption result file {share_file} does not exist."))
            return
        with open(share_file, "r", encoding="utf-8") as f:
            share_data = json.load(f)
        try:
            # 反序列化部分解密结果
            partial_result = Tracer.deserialize_decrypt_result(share_data, pp)
            partial_results.append(partial_result)
            # 从 tracer 的 pub 文件中提取 pub_share
            tracer_id = share_data.get("tracer_id", None)
            if tracer_id is None:
                print(t(f"部分解密结果文件 {share_file} 中没有 tracer_id。", f"Partial decryption result file {share_file} does not contain tracer_id."))
                return
            # 构造 tracer 的 pub 文件名
            tracer_pub_file = f"config/tracer/tracer_{tracer_id}_pub.json"
            if os.path.exists(tracer_pub_file):
                with open(tracer_pub_file, "r", encoding="utf-8") as pubf:
                    pub_data = json.load(pubf)
                pub_share_str = pub_data.get("pub_share", None)
                if pub_share_str is not None:
                    D_list.append(point_from_string(pub_share_str, pp.F, pp.E))
                else:
                    D_list.append(None)
            else:
                D_list.append(None)
        except Exception as e:
            print(t(f"部分解密结果文件 {share_file} 解析失败: {e}", f"Failed to parse partial decryption result file {share_file}: {e}"))
            return

    # 组合恢复PID
    try:
        # print(D_list)
        PID = Tracer.combine(D_list, partial_results, signature, pp)
    except Exception as e:
        print(t(f"PID恢复失败: {e}", f"Failed to recover PID: {e}"))
        return

    print(t(f"恢复出的PID为: {point_to_string(PID)}", f"Recovered PID: {point_to_string(PID)}"))
    # 通过在user文件夹检索pid，找到对应的user_id，并输出user_id
    user_dir = "config/user"
    for user_file in os.listdir(user_dir):
        if user_file.endswith("_key.json"):
            with open(os.path.join(user_dir, user_file), "r", encoding="utf-8") as f:
                user_data = json.load(f)
                if user_data.get("pid") == point_to_string(PID):
                    print(t(f"检索出签名用户 {user_data.get('user_id')}", f"Found user {user_data.get('user_id')}"))
                    break

def main():
    parser = argparse.ArgumentParser(description="libTARS CLI")
    subparsers = parser.add_subparsers(dest="module", required=True, help="模块: kgc 或 user")

    # KGC 子命令
    kgc_parser = subparsers.add_parser("kgc", help=t("KGC相关操作", "KGC related operations"))
    kgc_subparsers = kgc_parser.add_subparsers(dest="kgc_command", required=True)

    # kgc setup
    kgc_setup_parser = kgc_subparsers.add_parser("setup", help=t("生成系统主密钥和公钥Q", "Generate system master key and public key Q"))
    kgc_setup_parser.add_argument("-p", "--params", help=t("系统参数文件 (params.json)", "System parameter file (params.json)"))
    kgc_setup_parser.add_argument("-k", "--key", help=t("KGC密钥文件 (key.json)", "KGC key file (key.json)"))
    kgc_setup_parser.set_defaults(func=kgc_setup)

    # kgc tracerkeygen
    kgc_tracerkeygen_parser = kgc_subparsers.add_parser("tracerkeygen", help=t("生成所有追踪者密钥份额", "Generate all tracer key shares"))
    kgc_tracerkeygen_parser.add_argument("-p", "--params", help=t("系统参数文件 (params.json)", "System parameter file (params.json)"))
    kgc_tracerkeygen_parser.add_argument("-k", "--key", help=t("KGC密钥文件 (key.json)", "KGC key file (key.json)"))
    kgc_tracerkeygen_parser.add_argument("-o", "--output", help=t("输出所有追踪者密钥的文件", "Output file for all tracer keys"))
    kgc_tracerkeygen_parser.add_argument("-sf", "--single-key-file-fmt", help=t("单个追踪者密钥文件格式", "Single tracer key file format"))
    kgc_tracerkeygen_parser.add_argument("-spf", "--single-public-key-file-fmt", help=t("单个追踪者公钥文件格式", "Single tracer public key file format"))
    kgc_tracerkeygen_parser.set_defaults(func=kgc_tracerkeygen)

    # User 子命令
    user_parser = subparsers.add_parser("user", help=t("用户相关操作", "User related operations"))
    user_subparsers = user_parser.add_subparsers(dest="user_command", required=True)

    # user keygen
    user_keygen_parser = user_subparsers.add_parser("keygen", help=t("生成用户密钥", "Generate user key"))
    user_keygen_parser.add_argument("user_id", help=t("用户ID", "User ID"))
    user_keygen_parser.add_argument("-p", "--params", help=t("系统参数文件 (params.json)", "System parameter file (params.json)"))
    user_keygen_parser.add_argument("-k", "--key", help=t("用户密钥文件", "User key file"))
    user_keygen_parser.add_argument("-pk", "--public-key", help=t("用户公钥文件", "User public key file"))
    user_keygen_parser.add_argument("-d", "--user-dir", help=t("用户密钥目录", "User key directory"))
    user_keygen_parser.set_defaults(func=user_keygen)

    # user sign
    user_sign_parser = user_subparsers.add_parser("sign", help=t("用户环签名消息", "User ring sign a message"))
    user_sign_parser.add_argument("user_id", help=t("用户ID", "User ID"))
    user_sign_parser.add_argument("message", help=t("要签名的消息", "Message to sign"))
    user_sign_parser.add_argument("ring", nargs="+", help=t("环用户ID列表或文件", "Ring user ID list or file"))
    user_sign_parser.add_argument("-p", "--params", help=t("系统参数文件 (params.json)", "System parameter file (params.json)"))
    user_sign_parser.add_argument("-k", "--key", help=t("用户密钥文件", "User key file"))
    user_sign_parser.add_argument("-d", "--user-dir", help=t("用户密钥目录", "User key directory"))
    user_sign_parser.add_argument("-e", "--event", help=t("事件字段 (event)", "Event field (event)"))
    user_sign_parser.add_argument("-o", "--output", help=t("签名输出文件", "Signature output file"))
    user_sign_parser.set_defaults(func=user_sign)

    # user verify
    user_verify_parser = user_subparsers.add_parser("verify", help=t("验证用户环签名", "Verify user ring signature"))
    user_verify_parser.add_argument("message", help=t("要验证的消息", "Message to verify"))
    user_verify_parser.add_argument("-p", "--params", help=t("系统参数文件 (params.json)", "System parameter file (params.json)"))
    user_verify_parser.add_argument("-d", "--user-dir", help=t("用户密钥目录", "User key directory"))
    user_verify_parser.add_argument("-i", "--input", required=True, help=t("签名输入文件", "Signature input file"))
    user_verify_parser.set_defaults(func=user_verify)

    # Tracer 子命令
    tracer_parser = subparsers.add_parser("tracer", help=t("追踪者相关操作", "Tracer related operations"))
    tracer_subparsers = tracer_parser.add_subparsers(dest="tracer_command", required=True)

    # tracer partial_decrypt
    tracer_partial_decrypt_parser = tracer_subparsers.add_parser("partial_decrypt", help=t("追踪者对签名进行部分解密", "Tracer partial decrypt a signature"))
    tracer_partial_decrypt_parser.add_argument("tracer_id", help=t("追踪者ID", "Tracer ID"))
    tracer_partial_decrypt_parser.add_argument("-i", "--input", required=True, help=t("签名输入文件", "Signature input file"))
    tracer_partial_decrypt_parser.add_argument("-k", "--key", required=True, help=t("追踪者密钥文件", "Tracer key file"))
    tracer_partial_decrypt_parser.add_argument("-p", "--params", help=t("系统参数文件 (params.json)", "System parameter file (params.json)"))
    tracer_partial_decrypt_parser.add_argument("-o", "--output", help=t("输出部分解密结果文件", "Output partial decryption result file"))
    tracer_partial_decrypt_parser.set_defaults(func=tracer_partial_decrypt)

    # tracer recover_pid
    tracer_recover_parser = tracer_subparsers.add_parser("recover", help=t("追踪者恢复PID", "Tracer recover PID"))
    tracer_recover_parser.add_argument("-i", "--input", required=True, help=t("签名输入文件", "Signature input file"))
    tracer_recover_parser.add_argument("-s", "--shares", required=True, help=t("部分解密结果文件列表", "Partial decryption result file list"))
    tracer_recover_parser.add_argument("-p", "--params", help=t("系统参数文件 (params.json)", "System parameter file (params.json)"))
    tracer_recover_parser.add_argument("-o", "--output", help=t("输出PID文件", "Output PID file"))
    tracer_recover_parser.set_defaults(func=tracer_combine)

    args = parser.parse_args()
    # 兼容调用
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
