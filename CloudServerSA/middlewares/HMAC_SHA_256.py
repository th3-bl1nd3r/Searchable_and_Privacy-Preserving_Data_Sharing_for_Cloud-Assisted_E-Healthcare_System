import hashlib
import hmac
from middlewares.Conversion import int_to_bytes


def hmac_sha256(key, message):
    key_bytes = int_to_bytes(key)
    hmac_digest = hmac.new(key_bytes, message, hashlib.sha256).digest()
    return hmac_digest
