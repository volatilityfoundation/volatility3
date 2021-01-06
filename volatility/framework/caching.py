import functools
import volatility

DISABLED = False

def lru_cache(*args, **kwargs):
    if DISABLED:
        return lambda x: x
    return functools.lru_cache(*args, **kwargs)
