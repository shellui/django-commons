"""Minimal Django settings for shellui-django unit tests."""

from datetime import timedelta

SECRET_KEY = 'test-secret-key-not-for-production'
DEBUG = True
INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'rest_framework',
]
MIDDLEWARE: list[str] = []
ROOT_URLCONF = 'shellui_django.mcp.tests.mcp_routing_urlconf'
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}
USE_TZ = True
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}
AUTH_RATE_LIMIT_ENABLED = False

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
    'SIGNING_KEY': 'test-signing-key',
    'ALGORITHM': 'HS256',
    'ISSUER': 'https://identity.example.com',
}
