"""冒烟测试：骨架阶段仅验证包可导入。"""


def test_import() -> None:
    import ekm
    from ekm.api import app  # noqa: F401

    assert ekm.KeyManagementService is not None
