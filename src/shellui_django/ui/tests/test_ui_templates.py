"""Tests for shared Shellui card and error templates."""

from django.template.loader import render_to_string


def test_card_base_renders_shellui_chrome():
    html = render_to_string('shellui_ui/card_base.html', {'page_language': 'fr'})
    assert 'lang="fr"' in html
    assert '#logo-shellui-mark' in html
    assert 'static/css/site.css' in html
    assert 'localStorage.getItem("theme")' in html
    assert '—' not in html
    assert '–' not in html


def test_error_template_renders_status_and_copy():
    html = render_to_string(
        'shellui_ui/error.html',
        {
            'status_code': 404,
            'title': 'Page not found',
            'message': 'This page does not exist.',
            'home_label': 'Back to home',
        },
    )
    assert 'data-status="404"' in html
    assert 'Page not found</h1>' in html
    assert 'This page does not exist.' in html
    assert 'Back to home' in html
    assert '#logo-shellui-mark' in html
