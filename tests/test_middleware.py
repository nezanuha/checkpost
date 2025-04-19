from django.test import TestCase, RequestFactory
from django.http import HttpResponse
from django.contrib.sessions.middleware import SessionMiddleware
from checkpost.middleware import CheckpostMiddleware


def dummy_view(request):
    if request.is_sus:
        return HttpResponse("Blocked", status=403)
    return HttpResponse("OK", status=200)


class CheckpostMiddlewareTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = CheckpostMiddleware(get_response=dummy_view)

    def add_session_to_request(self, request):
        middleware = SessionMiddleware(lambda x: x)
        middleware.process_request(request)
        request.session.save()

    def test_request_allowed_on_first_visit(self):
        request = self.factory.get('/')
        request.META['HTTP_USER_AGENT'] = 'test-agent'
        self.add_session_to_request(request)

        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(request.is_sus)

    def test_request_blocked_on_ip_change(self):
        request = self.factory.get('/')
        request.META['HTTP_USER_AGENT'] = 'test-agent'
        request.META['REMOTE_ADDR'] = '1.1.1.1'
        self.add_session_to_request(request)

        # First request (allowed, sets IP)
        first_response = self.middleware(request)
        self.assertEqual(first_response.status_code, 200)

        # Second request with same fingerprint
        # but different IP (should be blocked)
        request2 = self.factory.get('/')
        request2.META['HTTP_USER_AGENT'] = 'test-agent'
        request2.META['REMOTE_ADDR'] = '2.2.2.2'
        request2.session = request.session  # simulate same session

        # You MUST manually save session between requests
        request2.session.save()

        response2 = self.middleware(request2)
        self.assertEqual(response2.status_code, 403)
        self.assertTrue(request2.is_sus)
