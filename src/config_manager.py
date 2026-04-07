import json
import os
import logging
import copy
from collections.abc import Mapping

_log = logging.getLogger("Config")

from utils import get_exe_dir

DEFAULT_CONFIG = {
    "profile": "home",
    "autoblock": False,
    "autostart": True,
    "ai_thresholds": {"home": -0.30, "pme": -0.15, "datacenter": 0.00},
    "interface": None,
}


def deep_update(d, u):
    for k, v in u.items():
        if isinstance(v, Mapping):
            d[k] = deep_update(d.get(k, {}), v)
        else:
            d[k] = v
    return d


def get_config_path():
    root = get_exe_dir()
    config_dir = os.path.join(root, "config")
    os.makedirs(config_dir, exist_ok=True)
    return os.path.join(config_dir, "config.json")


def load_config(config_file=None):
    if config_file is None:
        config_file = get_config_path()

    config = copy.deepcopy(DEFAULT_CONFIG)

    if not os.path.exists(config_file):
        return config
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            user_config = json.load(f)
            return deep_update(config, user_config)
    except Exception as e:
        _log.warning(f"config.json invalido ou ilegivel, usando padrao: {e}")
        return config


def save_config(config_dict, config_file=None):
    if config_file is None:
        config_file = get_config_path()

    try:
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(config_dict, f, indent=4)
    except Exception as e:
        _log.error(f"Falha ao salvar config.json: {e}")
