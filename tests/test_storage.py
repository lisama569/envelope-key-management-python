"""本地密钥存储：版本归档不可变 + 落盘往返。"""

from __future__ import annotations

import logging

from ekm.crypto import generate_master_secret
from ekm.storage import KeyRecord, LocalKeyStore

logger = logging.getLogger(__name__)


def test_record_versions_and_persistence(tmp_path) -> None:
    path = tmp_path / "keys.json"
    store = LocalKeyStore(path)

    record = KeyRecord(key_id="k1", current_version=1, created_at="2026-09-22T00:00:00Z")
    record.master_secrets[1] = generate_master_secret()
    record.master_secrets[2] = generate_master_secret()
    record.current_version = 2
    store.save({"k1": record})

    loaded = LocalKeyStore(path).load()["k1"]
    assert loaded.versions() == [1, 2]
    assert loaded.current_version == 2
    # 历史版本密钥仍可取出用于解密
    assert loaded.secret_for(1) == record.secret_for(1)
    logger.info("归档验证 key_id=k1 versions=%s current=v%s 判定依据=历史版本密钥可重新加载",
                loaded.versions(), loaded.current_version)


def test_load_missing_returns_empty(tmp_path) -> None:
    assert LocalKeyStore(tmp_path / "nope.json").load() == {}
