import os

# 默认配置路径
DEFAULT_CONFIG_DIR = os.path.join(os.path.dirname(__file__), '../../config')
DEFAULT_PARAMS_PATH = os.path.join(DEFAULT_CONFIG_DIR, 'params.json')
DEFAULT_KGC_KEY_PATH = os.path.join(DEFAULT_CONFIG_DIR, 'kgc', 'key.json')

DEFAULT_TRACER_KEYS_DIR = os.path.join(DEFAULT_CONFIG_DIR, 'tracer')
DEFAULT_TRACER_KEYS_FILE = os.path.join(DEFAULT_TRACER_KEYS_DIR, 'tracer_keys.json')
DEFAULT_TRACER_SINGLE_KEY_FILE_FMT = os.path.join(DEFAULT_TRACER_KEYS_DIR, 'tracer_{}_key.json')
DEFAULT_TRACER_SINGLE_PUBLIC_KEY_FILE_FMT = os.path.join(DEFAULT_TRACER_KEYS_DIR, 'tracer_{}_pub.json')

DEFAULT_USER_KEYS_DIR = os.path.join(DEFAULT_CONFIG_DIR, 'user')
DEFAULT_USER_SINGLE_KEY_FILE_FMT = os.path.join(DEFAULT_USER_KEYS_DIR, 'user_{}_key.json')
DEFAULT_USER_SINGLE_PUBLIC_KEY_FILE_FMT = os.path.join(DEFAULT_USER_KEYS_DIR, 'user_{}_pub.json')