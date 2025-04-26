
[![PyPI - Downloads](https://img.shields.io/pypi/dm/checkpost)](https://pypi.org/project/checkpost/)
[![License](https://img.shields.io/github/license/nezanuha/checkpost)](https://github.com/nezanuha/checkpost/blob/master/LICENSE)
![PyPI - Version](https://img.shields.io/pypi/v/checkpost)
[![Secured](https://img.shields.io/badge/Security-Passed-green)](https://snyk.io/test/github/nezanuha/checkpost)


# Checkpost - Accurate Spam Detector, bot Detector -- Prevent malicious requests

Enhance your Django application's security by automatically detecting and blocking spam and fraudulent requests. This solution operates transparently in the background, eliminating the need for CAPTCHAs and ensuring a seamless user experience. By analyzing request patterns and behaviors, it effectively filters out malicious activities without compromising usability.

## Installation

```bash
pip install checkpost
```
---

## ✅ Usage

### 1. **Enable Sessions (Required)**

Checkpost uses sessions to help with request fingerprinting. Ensure sessions are properly configured in your `settings.py`:

```python
INSTALLED_APPS = [
    'django.contrib.sessions',
    ...
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    ...
]
```

### 2. **Add Middleware**

In your Django `settings.py`, add the `CheckpostMiddleware`:

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'checkpost.middleware.CheckpostMiddleware',  # 👈 Add checkpost after SessionMiddleware
]
```

### 3. **Enable Django Caching**

The spam detection system **requires Django’s cache system** to function properly. Make sure your cache backend is configured in `settings.py`.

#### Example using in-memory (development):
```python
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.dummy.DummyCache",
    },
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

### 4. Global Blocking Behavior

By default, suspicious requests are **automatically** blocked (raises `PermissionDenied`).  
To inspect and handle them manually in your views:

```python
CHECKPOST_BLOCK_GLOBALLY = False
```

### 5. **Using in Views**

You **don’t need to import or call anything manually**. The middleware sets `request.is_sus` automatically before views are called.

```python
def my_view(request):
    if getattr(request, 'is_sus', False):
        # Optionally log or store the suspicious activity here
        return HttpResponse("Access Denied", status=403)
    
    return HttpResponse("Welcome!")
```

## ⚙️ Configuration (Optional Settings)

All of these settings are **optional**. Omit them to use the built-in defaults.

| Setting                         | Default   | Description & When to Use                                                                                              |
|---------------------------------|-----------|-------------------------------------------------------------------------------------------------------------------------|
| `CHECKPOST_MISMATCH_THRESHOLD`  | `1`       | How many IP‐mismatches allowed before blocking. Increase if users may legitimately switch IPs (mobile networks, VPN). |
| `CHECKPOST_TRUSTED_IPS`         | `[]`      | List of IPs or CIDR ranges that **bypass** the IP change check. Useful for internal services, health‐checks, or VPNs. |
| `CHECKPOST_TRUSTED_USER_AGENTS` | `[]`      | List of regex patterns matching UAs to **bypass** the IP check. Use for known crawlers/bots or API clients.            |
| `CHECKPOST_BLOCK_GLOBALLY`      | `True`    | If `False`, middleware sets `request.is_sus` but does not raise. You must handle blocking in your views.              |
| `CHECKPOST_CACHE_TIMEOUT`       | 3600      | (Optional) Seconds until a stored IP or mismatch count expires. Lower for short‐lived sessions, higher to remember users longer|

### When to add Trusted IPs / UAs

- **Trusted IPs**:  
  - Internal cron jobs, monitoring, or deploy hooks with fixed IPs.  
  - Corporate or VPN egress ranges where legitimate users hop across subnets.

- **Trusted User-Agents**:  
  - Official search crawlers (e.g. Googlebot) whose UA you recognize.  
  - API clients that send a stable UA string.

> **Tip:** Start without any whitelists. Monitor your logs for false positives, and **only** add IPs or UA patterns when necessary.


---
## ⚠️ Notes

- If the cache is not available or misconfigured, spam detection will **gracefully skip checks** (and allow all requests).
- For best results, use a high-performance cache (Redis, Memcached, or `LocMemCache` in‐memory) in production.
- **Sessions and Caching are mandatory** for correct spam detection. If sessions or cache are unavailable, Checkpost will gracefully allow all traffic (fail-safe).
