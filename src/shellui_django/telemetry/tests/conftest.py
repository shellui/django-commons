import django
import pytest

from shellui_django.telemetry import _reset_for_tests


@pytest.fixture(scope='session', autouse=True)
def _django_ready():
    django.setup()


@pytest.fixture(autouse=True)
def _isolate_telemetry():
    _reset_for_tests()
    yield
    _reset_for_tests()
