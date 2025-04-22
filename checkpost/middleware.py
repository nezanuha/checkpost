import hashlib
import logging
from django.core.cache import caches
from django.core.exceptions import PermissionDenied
from django.conf import settings
logger = logging.getLogger(__name__)


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


class CheckpostMiddleware:
    def __init__(
        self, get_response,
        cache_alias='default',
        scope='security_check',
        timeout=3600
    ):
        self.get_response = get_response
        self.scope = scope
        self.timeout = timeout

        try:
            self.cache = caches[cache_alias]
        except Exception as e:
            logger.exception(f"Cache alias '{cache_alias}' is not configured.")
            raise RuntimeError(
                f"CheckpostMiddleware requires a valid cache alias. "
                f"Set '{cache_alias}' in CACHES setting. Original error: {e}"
            )

    def __call__(self, request):
        try:
            request.is_sus = self.is_suspicious(request)
        except Exception as e:
            logger.exception(f"Security detection failed: {e}")
            request.is_sus = False  # Allow request if error occurs

        # Decide blocking behavior based on setting
        block_globally = getattr(settings, 'CHECKPOST_BLOCK_GLOBALLY', True)

        if block_globally and request.is_sus:
            raise PermissionDenied("Suspicious request blocked.")

        return self.get_response(request)

    def is_suspicious(self, request):
        try:
            if not self.cache:
                logger.warning(
                    "CheckpostMiddleware: cache not initialized. Skipping check."
                )
                return False

            session_id = request.session.session_key
            if not session_id:
                _ = request.session.create()
                session_id = request.session.session_key

            """
            Return a unique cache key based on the user's fingerprint and
            IP address. This ensures throttling is applied consistently
            to the same user.
            """

            ip_address = get_client_ip(request)
            user_agent = request.META.get("HTTP_USER_AGENT", "")

            # Combine session ID, IP, and user agent
            # to create a unique fingerprint
            fingerprint_string = f"{session_id}:{ip_address}:{user_agent}"

            # Create a secure hash of the fingerprint
            fingerprint = hashlib.sha256(
                fingerprint_string.encode()
            ).hexdigest()

            if not fingerprint:
                logger.error(
                    "Suspicious behavior flagged."
                    "Access temporarily restricted"
                    "no fingerprint found"
                )
                request.is_sus = True
                return None

            # Check if the fingerprint already has an
            # associated IP in the cache
            stored_ip = self.cache.get(f"{self.scope}:{fingerprint}")

            if stored_ip != ip_address:
                # Block the request by raising a PermissionDenied exception
                logger.error(
                    "Suspicious behavior flagged."
                    "Access temporarily restricted"
                    "stored_ip and ip_address not matching"
                )
                request.is_sus = True
                return None
            else:
                # Store the IP address in the cache for the fingerprint
                # (on first request)
                self.cache.set(
                    f"{self.scope}:{fingerprint}",
                    ip_address,
                    timeout=self.timeout
                )
            # Set custom throttle status to indicate the request is allowed
            request.is_sus = False

            # Return a cache key based on the fingerprint and IP address
            return f'{self.scope}:{fingerprint}:{ip_address}'
        except Exception as e:
            logger.exception(f"Checkpost security detection error - {e}")
            return False
