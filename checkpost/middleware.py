import hashlib
import logging
from django.core.cache import caches

logger = logging.getLogger(__name__)  # Django logging


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


class CheckpostMiddleware:
    def __init__(
        self, get_response,
        cache_alias='default',
        scope='security-check',
        timeout=3600
    ):
        self.get_response = get_response
        try:
            self.cache = caches[cache_alias]
        except Exception as e:
            logger.error(f"Cache error: {e}")
            self.cache = None  # Fallback to disable detection
        self.scope = scope
        self.timeout = timeout

    def __call__(self, request):
        try:
            request.is_sus = self.is_suspicious(request)
        except Exception as e:
            logger.exception(f"Secuiry detection failed: {e}")
            request.is_sus = False  # Allow request by default if error occurs
        return self.get_response(request)

    def is_suspicious(self, request):
        try:
            session_id = request.session.session_key
            if not session_id:
                request.session.create()
                session_id = request.session.session_key

            ip_address = get_client_ip(request)
            user_agent = request.META.get("HTTP_USER_AGENT", "")
            fingerprint = hashlib.sha256(
                f"{session_id}:{ip_address}:{user_agent}".encode()
            ).hexdigest()

            if not self.cache:
                logger.warning(
                    "Checkpost: Cache not available. Skipping security check."
                )
                return False  # Allow by default if cache isn't working

            stored_ip = self.cache.get(f"{self.scope}:{fingerprint}")
            if stored_ip and stored_ip != ip_address:
                return True

            self.cache.set(
                f"{self.scope}:{fingerprint}",
                ip_address, timeout=self.timeout
            )
            return False
        except Exception as e:
            logger.exception(f"Checkpost security detection error - {e}")
            return False
