import os
import subprocess
import sys
import textwrap


def test_batch_export_survives_fork():
    script = textwrap.dedent(
        """
        import os
        for key in list(os.environ):
            if key.startswith('OTEL_') or key == 'DJANGO_SETTINGS_MODULE':
                os.environ.pop(key)
        from multiprocessing import get_context

        from opentelemetry import trace
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

        from shellui_django.telemetry import setup_telemetry

        exporter = InMemorySpanExporter()
        assert setup_telemetry(
            'shellui-identity',
            span_exporter=exporter,
            batch_export=True,
        )
        tracer = trace.get_tracer('shellui.parent')
        with tracer.start_as_current_span('before-fork'):
            pass
        assert trace.get_tracer_provider().force_flush(5000)

        def child(conn):
            child_tracer = trace.get_tracer('shellui.child')
            with child_tracer.start_as_current_span('after-fork'):
                pass
            flushed = trace.get_tracer_provider().force_flush(5000)
            names = [span.name for span in exporter.get_finished_spans()]
            conn.send((flushed, 'after-fork' in names))

        context = get_context('fork')
        parent, child_conn = context.Pipe(duplex=False)
        process = context.Process(target=child, args=(child_conn,))
        process.start()
        process.join(15)
        if process.exitcode != 0:
            raise SystemExit(f'child exit {process.exitcode}')
        flushed, found = parent.recv()
        if not flushed or not found:
            raise SystemExit(f'fork export failed flushed={flushed} found={found}')
        """
    )
    env = os.environ.copy()
    result = subprocess.run([sys.executable, '-c', script], check=False, capture_output=True, text=True, env=env)
    assert result.returncode == 0, result.stderr + result.stdout
