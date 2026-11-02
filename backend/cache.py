import json
import os

try:
    import redis
except Exception:  # pragma: no cover
    redis = None

try:
    from .config import REDIS_URL
except ImportError:  # pragma: no cover - supports running as a top-level module
    from config import REDIS_URL


class CacheClient:
    def __init__(self):
        self.enabled = redis is not None
        self.client = None
        if self.enabled:
            try:
                self.client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
                self.client.ping()
            except Exception:
                self.enabled = False
                self.client = None

    def get(self, key):
        if not self.enabled or self.client is None:
            return None
        try:
            value = self.client.get(key)
            if value is None:
                return None
            try:
                return json.loads(value)
            except Exception:
                return value
        except Exception:
            return None

    def set(self, key, value, ttl_seconds=300):
        if not self.enabled or self.client is None:
            return False
        try:
            payload = json.dumps(value)
            self.client.setex(key, ttl_seconds, payload)
            return True
        except Exception:
            return False

    def delete(self, key):
        if not self.enabled or self.client is None:
            return False
        try:
            self.client.delete(key)
            return True
        except Exception:
            return False


cache = CacheClient()
