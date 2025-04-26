# tests/test_middleware.py

from django.test import TestCase, RequestFactory, override_settings
from django.http import HttpResponse
from django.core.exceptions import PermissionDenied
from django.contrib.sessions.middleware import SessionMiddleware

from checkpost.middleware import CheckpostMiddleware

class DummyView:
    """A dummy view that always returns HTTP 200."""
    def __call__(self, request):
        return HttpResponse('ok')

@override_settings(
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}
)
class CheckpostMiddlewareTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        # Initialize middleware with our dummy view as the response handler
        self.middleware = CheckpostMiddleware(get_response=DummyView())

    def _get_request(self, ip, ua='test-agent', session_key=None):
        """
        Helper to build a RequestFactory GET request with a session.
        If session_key is provided, reuse it to simulate the same session.
        """
        request = self.factory.get('/', **{
            'HTTP_USER_AGENT': ua,
            'REMOTE_ADDR': ip
        })
        # Apply Django's SessionMiddleware so request.session is available
        SessionMiddleware(get_response=lambda r: None).process_request(request)

        if session_key:
            # Override the auto-generated session key
            request.session._session_key = session_key
        else:
            # Save to generate a new session_key
            request.session.save()
            session_key = request.session.session_key

        return request

    def test_first_request_passes(self):
        """
        On the very first request from an IP, the middleware should not flag it.
        """
        req = self._get_request('1.2.3.4')
        response = self.middleware(req)
        self.assertFalse(getattr(req, 'is_sus', False))
        self.assertEqual(response.status_code, 200)

    def test_block_default_threshold(self):
        """
        With the default threshold (1), a second request from a different IP
        in the same session should be blocked.
        """
        # First request from initial IP
        req1 = self._get_request('1.2.3.4')
        sid = req1.session.session_key
        self.middleware(req1)

        # Second request from a new IP, same session → should raise PermissionDenied
        req2 = self._get_request('5.6.7.8', session_key=sid)
        with self.assertRaises(PermissionDenied):
            self.middleware(req2)

    @override_settings(CHECKPOST_MISMATCH_THRESHOLD=2)
    def test_threshold_two(self):
        """
        When threshold is set to 2, the first IP mismatch is allowed,
        but the second mismatch in the same session should be blocked.
        """
        # Recreate middleware to pick up the overridden threshold
        self.middleware = CheckpostMiddleware(get_response=DummyView())

        # First request sets the baseline IP
        req1 = self._get_request('1.2.3.4')
        sid = req1.session.session_key
        self.middleware(req1)

        # First mismatch (allowed under threshold=2)
        req2 = self._get_request('5.6.7.8', session_key=sid)
        response2 = self.middleware(req2)
        self.assertFalse(getattr(req2, 'is_sus', False))

        # Second mismatch should now be blocked
        req3 = self._get_request('9.10.11.12', session_key=sid)
        with self.assertRaises(PermissionDenied):
            self.middleware(req3)
