import hashlib
import logging
import ipaddress
import re
from functools import lru_cache

from django.core.cache import caches
from django.core.exceptions import PermissionDenied
from django.conf import settings

logger = logging.getLogger(__name__)


def get_client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


@lru_cache(maxsize=1024)
def parse_ip(ip_str):
    try:
        return ipaddress.ip_address(ip_str)
    except ValueError:
        return None


class CheckpostMiddleware:
    def __init__(self, get_response,
                 cache_alias='default',
                 scope='security_check',
                 default_timeout=3600):
        self.get_response = get_response
        self.scope = scope

        # Allow override of cache timeout (seconds)
        self.timeout = getattr(settings, 'CHECKPOST_CACHE_TIMEOUT', default_timeout)

        # How many IP‐mismatches are allowed before blocking
        self.mismatch_threshold = getattr(settings, 'CHECKPOST_MISMATCH_THRESHOLD', 1)

        # Parse trusted IPs/CIDRs once
        raw_ips = getattr(settings, 'CHECKPOST_TRUSTED_IPS', [])
        self.trusted_networks = []
        for cidr in raw_ips:
            try:
                self.trusted_networks.append(ipaddress.ip_network(cidr))
            except ValueError:
                if logger.isEnabledFor(logging.WARNING):
                    logger.warning(f"Invalid trusted IP/CIDR skipped: {cidr}")

        # Compile trusted UA regexes once
        raw_uas = getattr(settings, 'CHECKPOST_TRUSTED_USER_AGENTS', [])
        self.trusted_ua_patterns = []
        for pat in raw_uas:
            try:
                self.trusted_ua_patterns.append(re.compile(pat))
            except re.error:
                if logger.isEnabledFor(logging.WARNING):
                    logger.warning(f"Invalid UA regex skipped: {pat}")

        # Skip whitelist work if none configured
        self.has_whitelist = bool(self.trusted_networks or self.trusted_ua_patterns)

        try:
            self.cache = caches[cache_alias]
        except Exception as e:
            logger.exception(f"Cache alias '{cache_alias}' is not configured.")
            raise RuntimeError(
                f"CheckpostMiddleware requires a valid cache alias. "
                f"Set '{cache_alias}' in CACHES. Error: {e}"
            )

    def __call__(self, request):
        try:
            request.is_sus = self.is_suspicious(request)
        except Exception as e:
            logger.exception(f"Security detection failed: {e}")
            request.is_sus = False

        if getattr(settings, 'CHECKPOST_BLOCK_GLOBALLY', True) and request.is_sus:
            raise PermissionDenied("Suspicious request blocked.")

        return self.get_response(request)

    def is_suspicious(self, request):
        if not self.cache:
            if logger.isEnabledFor(logging.WARNING):
                logger.warning("Cache not initialized, skipping security check.")
            return False

        sess = request.session
        if not sess.session_key:
            sess.create()
        sid = sess.session_key

        ip_str = get_client_ip(request)
        ua = request.META.get("HTTP_USER_AGENT", "")

        # Memoize fingerprint per-request
        if not hasattr(request, '_cp_fp'):
            raw = f"{sid}:{ua}"
            fp = hashlib.sha256(raw.encode()).hexdigest()
            request._cp_fp = fp
            request._cp_cache_key = f"{self.scope}:{fp}"
        cache_key = request._cp_cache_key
        mismatch_key = f"{cache_key}:mismatch_count"

        stored = self.cache.get_many([cache_key, mismatch_key])
        stored_ip = stored.get(cache_key)
        mismatch_count = stored.get(mismatch_key, 0)

        # Whitelist checks
        is_trusted = False
        if self.has_whitelist:
            ip_obj = parse_ip(ip_str)
            if ip_obj and any(ip_obj in net for net in self.trusted_networks):
                is_trusted = True
            elif any(p.search(ua) for p in self.trusted_ua_patterns):
                is_trusted = True

        # IP changed?
        if stored_ip and stored_ip != ip_str:
            if is_trusted:
                if logger.isEnabledFor(logging.INFO):
                    logger.info(f"Trusted override: {stored_ip} → {ip_str}")
                return False

            mismatch_count += 1
            self.cache.set(mismatch_key, mismatch_count, timeout=self.timeout)
            if logger.isEnabledFor(logging.WARNING):
                logger.warning(f"IP mismatch #{mismatch_count} for {cache_key}")

            if mismatch_count >= self.mismatch_threshold:
                if logger.isEnabledFor(logging.ERROR):
                    logger.error(f"Threshold {self.mismatch_threshold} exceeded: {stored_ip} → {ip_str}")
                return True
            return False

        # First-seen or matching IP
        if not stored_ip:
            self.cache.set(cache_key, ip_str, timeout=self.timeout)
        else:
            self.cache.delete(mismatch_key)

        return False
