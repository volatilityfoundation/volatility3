import functools
import volatility


def lru_cache(*args, **kwargs):
    if not volatility.CACHING:
        return lambda x: x
    raise Exception
    return functools.lru_cache(*args, **kwargs)
