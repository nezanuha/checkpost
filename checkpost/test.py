import hashlib
import logging
import ipaddress
import re

from django.core.cache import caches
from django.core.exceptions import PermissionDenied
from django.conf import settings

logger = logging.getLogger(__name__)


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


class CheckpostMiddleware:
    def __init__(self, get_response, cache_alias='default', scope='security_check', timeout=3600):
        self.get_response = get_response
        self.scope = scope
        self.timeout = timeout

        # Threshold for allowed mismatches before blocking
        self.mismatch_threshold = getattr(settings, 'CHECKPOST_MISMATCH_THRESHOLD', 1)

        # Load and parse trusted IPs/CIDRs
        raw_ips = getattr(settings, 'CHECKPOST_TRUSTED_IPS', [])
        self.trusted_networks = []
        for ip in raw_ips:
            try:
                self.trusted_networks.append(ipaddress.ip_network(ip))
            except ValueError:
                logger.warning(f"Invalid trusted IP/CIDR skipped: {ip}")

        # Load and compile trusted UA regexes
        raw_uas = getattr(settings, 'CHECKPOST_TRUSTED_USER_AGENTS', [])
        self.trusted_ua_patterns = []
        for pattern in raw_uas:
            try:
                self.trusted_ua_patterns.append(re.compile(pattern))
            except re.error:
                logger.warning(f"Invalid UA regex skipped: {pattern}")

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
            request.is_sus = False  # allow on internal errors

        if getattr(settings, 'CHECKPOST_BLOCK_GLOBALLY', True) and request.is_sus:
            raise PermissionDenied("Suspicious request blocked.")

        return self.get_response(request)

    def is_suspicious(self, request):
        try:
            if not self.cache:
                logger.warning("Cache not initialized, skipping check.")
                return False

            # Ensure session exists
            session_id = request.session.session_key
            if not session_id:
                request.session.create()
                session_id = request.session.session_key

            ip_str = get_client_ip(request)
            ua = request.META.get("HTTP_USER_AGENT", "")

            # Determine if this IP or UA is trusted
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                ip_obj = None
            is_trusted_ip = any(ip_obj in net for net in self.trusted_networks) if ip_obj else False
            is_trusted_ua = any(p.search(ua) for p in self.trusted_ua_patterns)

            # Build fingerprint without IP
            fingerprint_raw = f"{session_id}:{ua}"
            fp = hashlib.sha256(fingerprint_raw.encode()).hexdigest()
            cache_key = f"{self.scope}:{fp}"

            stored_ip = self.cache.get(cache_key)
            mismatch_count_key = f"{cache_key}:mismatch_count"
            mismatch_count = self.cache.get(mismatch_count_key, 0)

            # Check for IP change
            if stored_ip and stored_ip != ip_str:
                if is_trusted_ip or is_trusted_ua:
                    logger.info(
                        f"Whitelisted override for IP change. Stored: {stored_ip}, Got: {ip_str}, UA: {ua}"
                    )
                    return False

                # Increment mismatch counter
                mismatch_count += 1
                self.cache.set(mismatch_count_key, mismatch_count, timeout=self.timeout)
                logger.warning(f"IP mismatch #{mismatch_count} for fingerprint {fp}")

                # Block only if threshold reached
                if mismatch_count >= self.mismatch_threshold:
                    logger.error(
                        f"Suspicious behavior: stored IP {stored_ip} vs current {ip_str}. "
                        f"Threshold {self.mismatch_threshold} exceeded (count={mismatch_count})."
                    )
                    return True

                # Below threshold, do not block
                return False

            # On first match or first-seen, store IP and reset counter
            if not stored_ip:
                self.cache.set(cache_key, ip_str, timeout=self.timeout)
            else:
                # Reset mismatch counter on successful match
                self.cache.delete(mismatch_count_key)

            return False

        except Exception as e:
            logger.exception(f"Checkpost security detection error: {e}")
            return False


# ===============================
# Tests for CheckpostMiddleware
# ===============================
from django.test import TestCase, RequestFactory, override_settings
from django.http import HttpResponse
from django.core.exceptions import PermissionDenied
from django.contrib.sessions.middleware import SessionMiddleware

class DummyView:
    def __call__(self, request):
        return HttpResponse('ok')

@override_settings(CACHES={
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
})
class CheckpostMiddlewareTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = CheckpostMiddleware(get_response=DummyView())

    def _get_request(self, ip, ua='test-agent', session_key=None):
        request = self.factory.get('/', **{'HTTP_USER_AGENT': ua, 'REMOTE_ADDR': ip})
        SessionMiddleware(get_response=lambda r: None).process_request(request)
        if session_key:
            # reuse existing session key
            request.session._session_key = session_key
        else:
            # create new session key
            request.session.save()
            session_key = request.session.session_key
        return request

    def test_first_request_not_suspicious(self):
        req = self._get_request('1.2.3.4')
        response = self.middleware(req)
        self.assertFalse(getattr(req, 'is_sus'))
        self.assertEqual(response.status_code, 200)

    def test_block_on_ip_change_default_threshold(self):
        # First request sets initial IP
        req1 = self._get_request('1.2.3.4')
        sid = req1.session.session_key
        self.middleware(req1)
        # Second request with same session but different IP
        req2 = self._get_request('5.6.7.8', session_key=sid)
        with self.assertRaises(PermissionDenied):
            self.middleware(req2)

    @override_settings(CHECKPOST_MISMATCH_THRESHOLD=2)
    def test_threshold_two_allows_one_mismatch(self):
        self.middleware = CheckpostMiddleware(get_response=DummyView())
        req1 = self._get_request('1.2.3.4')
        sid = req1.session.session_key
        self.middleware(req1)
        req2 = self._get_request('5.6.7.8', session_key=sid)
        # first mismatch, not blocked
        response2 = self.middleware(req2)
        self.assertFalse(getattr(req2, 'is_sus'))
        # second mismatch exceeds threshold
        req3 = self._get_request('9.10.11.12', session_key=sid)
        with self.assertRaises(PermissionDenied):
            self.middleware(req3)
