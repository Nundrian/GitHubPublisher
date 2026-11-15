import json

import pytest

from publisher.config import ConfigError, load_config


def _cfg(tmp_path, **over):
    base = {"schema": 1, "data_dir": str(tmp_path / "d"), "github": {"owner": "Nundrian"},
            "projects": {"a": {"source": str(tmp_path), "repo": "A"}}}
    base.update(over)
    p = tmp_path / "c.json"
    p.write_text(json.dumps(base))
    return p


def test_valid(tmp_path):
    assert load_config(_cfg(tmp_path)).projects["a"].repo == "A"


@pytest.mark.parametrize("over,msg", [
    ({"listen_host": "0.0.0.0"}, "loopback"),
    ({"projects": {"a": {"source": "/x", "repo": "safe-route-regional-data"}}}, "protected"),
    ({"projects": {"a": {"source": "/x", "repo": "R"}, "b": {"source": "/y", "repo": "r"}}}, "another"),
    ({"projects": {"A_B": {"source": "/x", "repo": "R"}}}, "alias"),
    ({"projects": {"a": {"source": "relative", "repo": "R"}}}, "absolute"),
    ({"projects": {"a": {"source": "/x", "repo": "../evil"}}}, "repo"),
    ({"github": {"owner": "bad/owner"}}, "owner"),
    ({"projects": {"a": {"source": "/x", "repo": "R", "reviewed": [{"path": "x", "sha256": "abc"}]}}}, "sha256"),
])
def test_invalid(tmp_path, over, msg):
    with pytest.raises(ConfigError, match=msg):
        load_config(_cfg(tmp_path, **over))
