
[![PyPI - Downloads](https://img.shields.io/pypi/dm/checkpost)](https://pypi.org/project/checkpost/)
[![License](https://img.shields.io/github/license/nezanuha/checkpost)](https://github.com/nezanuha/checkpost/blob/master/LICENSE)
![PyPI - Version](https://img.shields.io/pypi/v/checkpost)
[![Secured](https://img.shields.io/badge/Security-Passed-green)](https://snyk.io/test/github/nezanuha/checkpost)


# Checkpost - Accurate Spam Detector, bot Detector

Enhance your Django application's security by automatically detecting and blocking spam and fraudulent requests. This solution operates transparently in the background, eliminating the need for CAPTCHAs and ensuring a seamless user experience. By analyzing request patterns and behaviors, it effectively filters out malicious activities without compromising usability.

## Installation

```bash
pip install checkpost
```
---

## ✅ Usage

### 1. **Add Middleware**

In your Django `settings.py`, add the `CheckpostMiddleware`:

```python
MIDDLEWARE = [
    # Other middleware...
    'checkpost.middleware.CheckpostMiddleware',  # 👈 Add this
]
```

### 2. **Enable Django Caching**

The spam detection system **requires Django’s cache system** to function properly. Make sure your cache backend is configured in `settings.py`.

#### Example using in-memory (development):
```python
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "checkpost",
    }
}
```

#### Example using Redis (recommended for production):
```python
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
    }
}
```

### 3. Customize Blocking Behavior
By default, Checkpost blocks suspicious requests globally in middleware.

To handle suspicious activity manually in your views, disable global blocking:

```python
CHECKPOST_BLOCK_GLOBALLY = False
```

### 4. **Using in Views**

You **don’t need to import or call anything manually**. The middleware sets `request.is_sus` automatically before views are called.

```python
def my_view(request):
    if getattr(request, 'is_sus', False):
        # Optionally log or store the suspicious activity here
        return HttpResponse("Access Denied", status=403)
    
    return HttpResponse("Welcome!")
```
---
## ⚠️ Notes

- If the cache is not available or misconfigured, spam detection will **gracefully skip checks** (and allow all requests).
- For accurate detection and fingerprinting, caching is **strongly recommended**.
