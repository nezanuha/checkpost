# Checkpost - Spam Detector

Enhance your Django application's security by automatically detecting and blocking spam and fraudulent requests. This solution operates transparently in the background, eliminating the need for CAPTCHAs and ensuring a seamless user experience. By analyzing request patterns and behaviors, it effectively filters out malicious activities without compromising usability.

## Installation

```bash
pip install checkpost
```


Absolutely — here’s how you can clearly document **cache requirement and usage** in your package’s `README.md` or setup docs.

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

### 3. **Using in Views**

You **don’t need to import or call anything manually**. The middleware sets `request.is_sus` automatically before views are called.

```python
def my_view(request):
    if request.is_sus:
        return HttpResponse("Blocked", status=403)

    return HttpResponse("Welcome!")
```

---

## ⚠️ Notes

- If the cache is not available or misconfigured, spam detection will **gracefully skip checks** (and allow all requests).
- For accurate detection and fingerprinting, caching is **strongly recommended**.

---

Would you like this formatted in Markdown so you can copy it straight into your package’s README?
