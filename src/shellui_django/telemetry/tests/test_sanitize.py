from shellui_django.telemetry._sanitize import redact_query, redact_sql, redact_url, sanitize_attributes


def test_sql_literals_are_removed_and_placeholders_stay():
    statement = redact_sql(
        "SELECT * FROM users WHERE email = 'ada@example.com' AND id = 42 AND other = %s AND ref = $1"
    )
    assert 'ada@example.com' not in statement
    assert '42' not in statement
    assert '%s' in statement
    assert '$1' in statement
    assert 'SELECT' in statement


def test_sql_dollar_quotes_comments_and_identifiers():
    assert 'secret' not in redact_sql('SELECT $$secret$$')
    assert 'secret' not in redact_sql('SELECT $tag$secret$tag$')
    assert 'hunter2' not in redact_sql('SELECT 1 -- password=hunter2')
    assert 'hunter2' not in redact_sql('SELECT 1 /* password=hunter2 */')
    assert redact_sql('SELECT col1 FROM t') == 'SELECT col1 FROM t'


def test_query_and_url_redaction():
    assert redact_query('token=abc&page=2') == 'token=REDACTED&page=2'
    url = redact_url('https://user:pw@identity.internal/v1/me?access_token=abc&page=2')
    assert 'abc' not in url
    assert 'user:pw' not in url
    assert 'REDACTED:REDACTED@identity.internal' in url
    assert 'page=2' in url
    assert '/v1/me' in url
    target = redact_url('/widgets?token=abc&q=kept')
    assert 'abc' not in target
    assert 'q=kept' in target


def test_span_attributes_drop_secrets():
    sanitized = sanitize_attributes(
        {
            'db.statement': "UPDATE users SET email = 'ada@example.com' WHERE id = 7",
            'db.statement.parameters': ('ada@example.com',),
            'db.query.parameter.0': 'ada@example.com',
            'http.request.header.authorization': ('Bearer secret',),
            'http.request.header.cookie': ('sid=secret',),
            'http.request.header.content_type': ('application/json',),
            'http.request.body': 'secret body',
            'url.query': 'token=abc&page=2',
            'url.full': 'https://identity.internal/v1/me?token=abc&page=2',
            'http.target': '/v1/me?code=abc&page=2',
        }
    )
    assert 'ada@example.com' not in sanitized['db.statement']
    assert '7' not in sanitized['db.statement'].split()
    assert 'db.statement.parameters' not in sanitized
    assert 'db.query.parameter.0' not in sanitized
    assert 'http.request.header.authorization' not in sanitized
    assert 'http.request.header.cookie' not in sanitized
    assert 'http.request.body' not in sanitized
    assert sanitized['http.request.header.content_type'] == ('application/json',)
    assert 'abc' not in sanitized['url.query']
    assert 'page=2' in sanitized['url.query']
    assert 'abc' not in sanitized['url.full']
    assert 'abc' not in sanitized['http.target']
