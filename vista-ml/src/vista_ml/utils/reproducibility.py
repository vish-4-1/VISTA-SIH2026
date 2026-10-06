from __future__ import annotations

import os
import random

import numpy as np


def set_random_seed(seed: int = 42) -> None:
    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)
    try:
        import sklearn

        sklearn.set_config(print_changed_only=False)
    except Exception:
        pass
    try:
        import xgboost as xgb

        xgb.set_config(verbosity=0)
    except Exception:
        pass
