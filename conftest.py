"""Pytest bootstrap. MCP imports read Django settings during collection."""

import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.django_settings')
