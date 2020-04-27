
from .context import get_tools_from_ldap


def test_tools_search(monkeypatch, ldap_conn):
    def mock_pg_search(*args, **kwargs):
        groups = [
            {
                "attributes": {
                    "cn": ["tools.example"],
                    "uidNumber": 50020,
                    "homeDirectory": "/data/project/example",
                }
            }
        ]
        for group in groups:
            yield group
    monkeypatch.setattr(
        ldap_conn.extend.standard, "paged_search", mock_pg_search
    )
    tools = get_tools_from_ldap(ldap_conn, "tools")
    assert tools["example"].id == 50020
    assert tools["example"].name == "example"
    assert tools["example"].home == "/data/project/example"
