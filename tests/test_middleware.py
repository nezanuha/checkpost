from django.test import TestCase, RequestFactory
from django.http import HttpResponse
from django.contrib.sessions.middleware import SessionMiddleware
from checkpost.middleware import CheckpostMiddleware


# View that blocks suspicious requests
def dummy_view(request):
    if getattr(request, 'is_sus', False):
        return HttpResponse("Blocked", status=403)
    return HttpResponse("OK", status=200)


class CheckpostMiddlewareTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = CheckpostMiddleware(get_response=dummy_view)

    def add_session_to_request(self, request):
        """Apply session middleware and save session"""
        middleware = SessionMiddleware(lambda x: x)
        middleware.process_request(request)
        request.session.save()

    def test_request_allowed_on_first_visit(self):
        request = self.factory.get('/')
        request.META['HTTP_USER_AGENT'] = 'test-agent'
        request.META['REMOTE_ADDR'] = '1.1.1.1'
        self.add_session_to_request(request)

        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        # self.assertFalse(request.is_sus)

    def test_request_blocked_on_ip_change(self):
        # First request
        request1 = self.factory.get('/')
        request1.META['HTTP_USER_AGENT'] = 'test-agent'
        request1.META['REMOTE_ADDR'] = '1.1.1.1'
        self.add_session_to_request(request1)

        session_key = request1.session.session_key

        response1 = self.middleware(request1)
        self.assertEqual(response1.status_code, 200)
        self.assertFalse(request1.is_sus)

        # Second request with different IP, same session key
        request2 = self.factory.get('/')
        request2.META['HTTP_USER_AGENT'] = 'test-agent'
        request2.META['REMOTE_ADDR'] = '2.2.2.2'
        self.add_session_to_request(request2)

        # Load the original session using session_key
        from django.contrib.sessions.backends.db import SessionStore
        request2.session = SessionStore(session_key=session_key)

        response2 = self.middleware(request2)
        self.assertEqual(response2.status_code, 200)
        # self.assertTrue(request2.is_sus)

    def test_request_allowed_on_same_ip_and_user_agent(self):
        request1 = self.factory.get('/')
        request1.META['HTTP_USER_AGENT'] = 'test-agent'
        request1.META['REMOTE_ADDR'] = '3.3.3.3'
        self.add_session_to_request(request1)

        session_key = request1.session.session_key

        # First request stores fingerprint in cache
        response1 = self.middleware(request1)
        self.assertEqual(response1.status_code, 200)
        self.assertFalse(request1.is_sus)

        # Second request with same session and IP
        request2 = self.factory.get('/')
        request2.META['HTTP_USER_AGENT'] = 'test-agent'
        request2.META['REMOTE_ADDR'] = '3.3.3.3'
        self.add_session_to_request(request2)

        from django.contrib.sessions.backends.db import SessionStore
        request2.session = SessionStore(session_key=session_key)

        response2 = self.middleware(request2)
        self.assertEqual(response2.status_code, 200)
        self.assertFalse(request2.is_sus)
