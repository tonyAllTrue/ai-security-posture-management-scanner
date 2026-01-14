import random
import time
import threading
import requests

import src.alltrue_scanner.config as config

def get_jwt_token(api_key: str, retries: int = 5, base_delay: float = 1.0, max_delay: float = 30.0) -> str:
    endpoint = f"{config.API_URL}/v1/auth/issue-jwt-token"
    headers = {"X-API-Key": api_key, "Accept": "application/json"}
    attempt = 0
    while True:
        attempt += 1
        try:
            resp = requests.post(endpoint, headers=headers, timeout=30)
            resp.raise_for_status()
            token = resp.json()["access_token"]
            return token
        except requests.HTTPError as e:
            code = getattr(e.response, "status_code", None)
            if code and 500 <= code < 600 and attempt < retries:
                delay = min(max_delay, base_delay * (2 ** (attempt - 1))) * (0.8 + 0.4 * random.random())
                print(f"[auth] 5xx from JWT endpoint (attempt {attempt}/{retries}); retrying in {delay:.1f}s")
                time.sleep(delay)
                continue
            raise
        except requests.RequestException:
            if attempt < retries:
                delay = min(max_delay, base_delay * (2 ** (attempt - 1))) * (0.8 + 0.4 * random.random())
                print(f"[auth] transient error (attempt {attempt}/{retries}); retrying in {delay:.1f}s")
                time.sleep(delay)
                continue
            raise

_thread_local = threading.local()

def get_thread_jwt_token() -> str:
    if not hasattr(_thread_local, 'jwt_token'):
        _thread_local.jwt_token = get_jwt_token(config.API_KEY)
        if config.LOG_JWT_THREADS:
            print(f"[+] JWT token obtained for thread {threading.current_thread().name}")
    return _thread_local.jwt_token

