# Test fixture for py-endpoint-auth.yml
import os

CF_HEADER = "Cf-Access-Authenticated-User-Email"


def current_user(request):
    # ruleid: py-access-identity-header-trusted
    return request.headers.get(CF_HEADER)


def current_user_inline(request):
    # ruleid: py-access-identity-header-trusted
    return request.headers.get("cf-access-authenticated-user-email", "")


def content_type(request):
    # ok: py-access-identity-header-trusted
    return request.headers.get("content-type")


API_KEY = os.environ.get("SERVICE_API_KEY", "")


def check(provided):
    # ruleid: py-auth-fails-open-when-secret-unset
    if API_KEY and provided != API_KEY:
        raise PermissionError("unauthorized")
    return True


def check_closed(provided):
    # ok: py-auth-fails-open-when-secret-unset
    if not API_KEY or provided != API_KEY:
        raise PermissionError("unauthorized")
    return True


# ruleid: py-hardcoded-secret-fallback
TOKEN = os.environ.get("UPSTREAM_TOKEN", "f00dBabe1234567890abcdef")
# ok: py-hardcoded-secret-fallback
REGION = os.environ.get("REGION", "us-central1-default")


def match(candidate, entity_key):
    # ok: py-auth-fails-open-when-secret-unset
    if entity_key and candidate != entity_key:
        return False
    return True


# ok: py-hardcoded-secret-fallback
SECRET_ID = os.environ.get("SECRET_ID_ENV", "service-api-key")
# ok: py-hardcoded-secret-fallback
ACCESS_TOKEN_FILE = os.environ.get("ACCESS_TOKEN_FILE", "/var/run/token2024abc.json")
