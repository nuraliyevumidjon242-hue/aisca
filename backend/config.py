import os


def get_env(name: str, default: str | None = None, *, required: bool = False) -> str | None:
    value = os.getenv(name, default)
    if required and value is None:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


APP_NAME = get_env('AISCA_APP_NAME', 'AISCA Security Platform')
DATABASE_PATH = get_env('AISCA_DB_PATH', 'scans.db')
DATABASE_URL = get_env('DATABASE_URL') or get_env('AISCA_DATABASE_URL')
REDIS_URL = get_env('REDIS_URL') or get_env('AISCA_REDIS_URL', 'redis://redis:6379/0')
API_BASE_URL = get_env('AISCA_API_BASE_URL', 'http://localhost:8000')
FRONTEND_BASE_URL = get_env('AISCA_FRONTEND_BASE_URL', 'http://localhost:3000')
