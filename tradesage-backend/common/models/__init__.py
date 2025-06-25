"""common.models package

This package previously shadowed the legacy module ``common/models.py`` which
contains the actual SQLAlchemy ORM model definitions such as ``BaseUser`` and
``Tenant``.  Because Python gives package directories precedence over modules
with the same dotted path, importing ``common.models`` would load this package
instead of the legacy module, causing ``ImportError`` for those symbols.

To maintain backward-compatibility without large scale refactoring we
re-export the required symbols from the legacy module so that
``from common.models import BaseUser`` continues to work.
"""

from importlib import util as _importlib_util  # noqa: E402
from importlib import machinery as _importlib_machinery  # noqa: E402
from pathlib import Path as _Path  # noqa: E402
import sys as _sys  # noqa: E402

# Locate the legacy models file relative to this __init__.py (…/common/models.py)
_legacy_path = (_Path(__file__).resolve().parent.parent / "models.py").as_posix()

_spec = _importlib_util.spec_from_file_location("common._legacy_models", _legacy_path)
_legacy_mod = _importlib_util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_legacy_mod)  # type: ignore[call-arg]

# Re-export public attributes required by the rest of the codebase
__all__ = [
    "BaseUser",
    "User",
    "Tenant",
    "TenantStatus",
    "UserRole",
    "ApiKey",
    "ApiUser",
    "Role",
    "BaseTenant",
]

globals().update({name: getattr(_legacy_mod, name) for name in __all__})

# Optionally re-export any other names that might be referenced dynamically
for _name in dir(_legacy_mod):
    if _name.startswith("_"):
        continue
    if _name not in globals():
        globals()[_name] = getattr(_legacy_mod, _name)
