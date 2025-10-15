import time
from threading import Lock


class SimpleRateLimiter:
    """A very small in-memory rate limiter for demonstration.

    Not suitable for multi-process deployments. Use Redis/Flask-Limiter in prod.
    """

    def __init__(self):
        self.calls = {}  # key -> list of timestamps
        self.lock = Lock()

    def allow(self, key: str, max_calls: int, period: int) -> bool:
        """Return True if the call is allowed for key under given rate.

        key: a string identifying the bucket (e.g., ip+endpoint)
        max_calls: maximum number of calls
        period: time window in seconds
        """
        now = time.time()
        cutoff = now - period
        with self.lock:
            lst = self.calls.get(key)
            if lst is None:
                self.calls[key] = [now]
                return True
            # remove old timestamps
            while lst and lst[0] < cutoff:
                lst.pop(0)
            if len(lst) < max_calls:
                lst.append(now)
                return True
            return False


_global_limiter = SimpleRateLimiter()


def allow_request(ip: str, endpoint: str, max_calls: int = 5, period: int = 60) -> bool:
    key = f"{ip}:{endpoint}"
    return _global_limiter.allow(key, max_calls, period)
