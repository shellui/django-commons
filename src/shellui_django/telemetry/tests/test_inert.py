import os
import subprocess
import sys
import textwrap


def _run(script: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    for key in list(env):
        if key.startswith('OTEL_'):
            env.pop(key)
    env.pop('DJANGO_SETTINGS_MODULE', None)
    return subprocess.run(
        [sys.executable, '-c', textwrap.dedent(script)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_import_is_inert_until_enabled():
    result = _run(
        """
        import sys
        import shellui_django
        import shellui_django.telemetry as telemetry
        from shellui_django.telemetry import counter, set_shellui_attributes

        assert telemetry.setup_telemetry('shellui-identity') is False
        assert telemetry.telemetry_enabled() is False
        counter('email_sent_total').add(1)
        set_shellui_attributes(company_id=1, user_id='abc')
        leaked = sorted(name for name in sys.modules if name.startswith('opentelemetry'))
        if leaked:
            raise SystemExit('leaked ' + ','.join(leaked))
        """
    )
    assert result.returncode == 0, result.stderr + result.stdout


def test_sdk_disabled_does_not_import_opentelemetry():
    result = _run(
        """
        import os
        import sys
        os.environ['OTEL_EXPORTER_OTLP_ENDPOINT'] = 'http://127.0.0.1:4318'
        os.environ['OTEL_SDK_DISABLED'] = 'true'
        import shellui_django.telemetry as telemetry
        assert telemetry.telemetry_enabled() is False
        assert telemetry.setup_telemetry('shellui-identity') is False
        leaked = sorted(name for name in sys.modules if name.startswith('opentelemetry'))
        if leaked:
            raise SystemExit('leaked ' + ','.join(leaked))
        """
    )
    assert result.returncode == 0, result.stderr + result.stdout
