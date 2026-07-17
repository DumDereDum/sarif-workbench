"""T-66: CRLF-переводы строк в хранимом сниппете не должны протекать в API.

`Finding.snippet` доверяется сервером как есть (см. `_serialize_finding` в
`routers/findings.py`) — оно приходит из swbmeta, который в принципе может
быть создан не нашим CLI (сторонний тул, ручной аплоад по спецификации).
Регрессия: `f.snippet.split("\n")` оставлял завершающие `\r` в каждой
строке `lines`, если исходный текст был CRLF (`\r\n`) или старым Mac-стилем
(`\r`) — фикс нормализует переводы строк перед разбиением.
"""
import uuid


def _unique_repo() -> str:
    return f"swb-test-{uuid.uuid4().hex[:8]}"


def test_crlf_snippet_has_no_carriage_return_in_api_response(client, db_session, upload_run):
    from swb_server.models import Finding

    run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/crlf.py", "start_line": 2}],
        repo=_unique_repo(),
    )
    items = client.get(f"/api/v1/runs/{run['run_id']}/findings").json()["items"]
    assert len(items) == 1
    finding_id = items[0]["id"]

    finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
    assert finding is not None
    finding.snippet = "line one\r\nline two\r\nline three"
    finding.snippet_start = 1
    finding.snippet_end = 3
    db_session.commit()

    resp = client.get(f"/api/v1/findings/{finding_id}")
    assert resp.status_code == 200
    body = resp.json()

    lines = body["snippet"]["lines"]
    assert lines == ["line one", "line two", "line three"]
    assert all("\r" not in line for line in lines)


def test_old_mac_style_cr_only_snippet_is_also_normalized(client, db_session, upload_run):
    """Одиночный `\\r` (старый Mac-стиль, без сопровождающего `\\n`) — тоже
    не должен просачиваться в API; consistency с CRLF-случаем выше."""
    from swb_server.models import Finding

    run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/cr_only.py", "start_line": 2}],
        repo=_unique_repo(),
    )
    items = client.get(f"/api/v1/runs/{run['run_id']}/findings").json()["items"]
    finding_id = items[0]["id"]

    finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
    assert finding is not None
    finding.snippet = "line one\rline two\rline three"
    finding.snippet_start = 1
    finding.snippet_end = 3
    db_session.commit()

    resp = client.get(f"/api/v1/findings/{finding_id}")
    assert resp.status_code == 200
    lines = resp.json()["snippet"]["lines"]
    assert lines == ["line one", "line two", "line three"]
    assert all("\r" not in line for line in lines)


def test_plain_lf_snippet_unaffected(client, db_session, upload_run):
    """Обычный (уже чистый `\\n`-разделённый) сниппет — без trailing
    newline, как всегда строит CLI — не должен менять поведение."""
    from swb_server.models import Finding

    run = upload_run(
        [{"rule_id": "CWE-89", "uri": "src/plain.py", "start_line": 2}],
        repo=_unique_repo(),
    )
    items = client.get(f"/api/v1/runs/{run['run_id']}/findings").json()["items"]
    finding_id = items[0]["id"]

    finding = db_session.query(Finding).filter(Finding.id == finding_id).first()
    assert finding is not None
    finding.snippet = "line one\nline two\nline three"
    finding.snippet_start = 1
    finding.snippet_end = 3
    db_session.commit()

    resp = client.get(f"/api/v1/findings/{finding_id}")
    assert resp.status_code == 200
    lines = resp.json()["snippet"]["lines"]
    assert lines == ["line one", "line two", "line three"]
