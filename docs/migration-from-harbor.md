# Migration Guide: Harbor → Lighthouse

This guide helps you migrate Harbor from its embedded identity module to the standalone Lighthouse library.

## Overview

Lighthouse extracts Harbor's `app/identity/` module into a reusable library with minimal changes to Harbor's codebase.

## Installation

Add lighthouse to Harbor's dependencies in `pyproject.toml`:

```toml
[project]
dependencies = [
    # ... existing dependencies
    "lighthouse-identity @ git+https://github.com/inspectioai/lighthouse.git@v0.1.0",
]
```

Then install:

```bash
cd /path/to/harbor
pip install -e .
```

## Import Changes

### File: `app/api/dependencies.py`

**Before:**
```python
from app.identity.cognito.provider import CognitoIdentityProvider
```

**After:**
```python
from lighthouse import CognitoIdentityProvider
```

### File: `app/core/services/tenant.py`

**Before:**
```python
from app.identity.base import IdentityProvider
from app.identity.models import PoolConfig
```

**After:**
```python
from lighthouse import IdentityProvider
from lighthouse.models import PoolConfig
```

### File: `app/core/services/user.py`

**Before:**
```python
from app.identity.base import IdentityProvider
from app.identity.models import PaginatedUsers
```

**After:**
```python
from lighthouse import IdentityProvider
from lighthouse.models import PaginatedUsers
```

## Exception Handling

Lighthouse has its own exception hierarchy. You have two options:

### Option A: Adapter Pattern (Recommended)

Keep Harbor exceptions, wrap Lighthouse exceptions in service layers:

**In `app/core/services/tenant.py`:**
```python
from lighthouse.exceptions import (
    PoolExistsError as LighthousePoolExistsError,
    IdentityProviderError as LighthouseIdentityProviderError,
)
from app.core.exceptions import PoolExistsError, IdentityProviderError

async def create_tenant(self, ...):
    try:
        pool = await self._identity.create_pool(...)
    except LighthousePoolExistsError as e:
        raise PoolExistsError(e.pool_name) from e
    except LighthouseIdentityProviderError as e:
        raise IdentityProviderError(e.message, e.operation) from e
```

**In `app/core/services/user.py`:**
```python
from lighthouse.exceptions import (
    UserExistsError as LighthouseUserExistsError,
    IdentityProviderError as LighthouseIdentityProviderError,
)
from app.core.exceptions import UserExistsError, IdentityProviderError

async def invite_user(self, ...):
    try:
        result = await self._identity.invite_user(...)
    except LighthouseUserExistsError as e:
        # Harbor adds tenant_id context
        raise UserExistsError(e.email, tenant_id=self.tenant_id) from e
    except LighthouseIdentityProviderError as e:
        raise IdentityProviderError(e.message, e.operation) from e
```

**Benefit:** Maintains Harbor-specific exception signatures and context (e.g., `tenant_id`).

### Option B: Direct Use (Simpler)

Use Lighthouse exceptions directly throughout Harbor:

**In `app/core/exceptions.py`:**
```python
# Remove these (now in lighthouse):
# - IdentityProviderError
# - PoolExistsError
# - UserExistsError

# Import from lighthouse instead:
from lighthouse.exceptions import (
    IdentityProviderError,
    PoolExistsError,
    UserExistsError,
)
```

Update exception handlers in services to catch Lighthouse exceptions directly.

**Drawback:** Loses Harbor-specific context like `tenant_id`.

**Recommendation:** Use Option A (Adapter Pattern) for cleaner separation.

## Delete Old Identity Module

After migration is complete and tested:

```bash
cd /path/to/harbor
rm -rf app/identity/
git add -A
git commit -m "Migrate to lighthouse library"
```

## Testing

### 1. Install Dependencies

```bash
cd /path/to/harbor
pip install -e .
```

### 2. Run Harbor Tests

```bash
pytest tests/
```

### 3. Run Type Checking

```bash
mypy app/
```

### 4. Run Linting

```bash
ruff check app/
```

## Validation Checklist

- [ ] All imports updated (dependencies.py, tenant.py, user.py)
- [ ] Exception handling updated (adapter or direct use)
- [ ] Harbor tests passing
- [ ] Type checking passing (mypy)
- [ ] Linting passing (ruff)
- [ ] Manual integration test successful
- [ ] Old `app/identity/` directory deleted
- [ ] Changes committed to git

## Manual Integration Test

Test the complete flow:

```bash
# Start Harbor
uvicorn app.main:app --reload --port 8080
```

```bash
# Create tenant
curl -X POST http://localhost:8080/tenants \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "test-tenant",
    "admin_email": "admin@test.com",
    "admin_display_name": "Admin User"
  }'

# List users
curl http://localhost:8080/tenants/test-tenant/users \
  -H "X-API-Key: your-api-key"

# Delete tenant
curl -X DELETE http://localhost:8080/tenants/test-tenant \
  -H "X-API-Key: your-api-key"
```

## Rollback Plan

If issues arise:

1. **Revert Git Commit:**
   ```bash
   git revert HEAD
   ```

2. **Remove Lighthouse Dependency:**
   ```bash
   # Edit pyproject.toml, remove lighthouse-identity line
   pip install -e .
   ```

3. **Restore `app/identity/`:**
   ```bash
   git checkout HEAD~1 -- app/identity/
   ```

## Updating to New Lighthouse Versions

```toml
# In pyproject.toml, change version tag
"lighthouse-identity @ git+https://github.com/inspectioai/lighthouse.git@v0.2.0",
```

```bash
# Reinstall
pip install -e . --force-reinstall
```

Test thoroughly after version updates.

## FAQ

### Q: Will this change Harbor's public API?

**A:** No. Harbor's REST API remains unchanged. This is an internal refactoring.

### Q: Do I need to update my Cognito pools?

**A:** No. Existing pools continue to work without changes.

### Q: Will tests need updating?

**A:** Import paths in tests need updating, but test logic remains the same.

### Q: What about performance?

**A:** No performance impact. Lighthouse is the same code, just in a different package.

### Q: Can I use Lighthouse in other services?

**A:** Yes! That's the point. Any service can now use Lighthouse for identity management.

## Support

Questions or issues? Check:
- Lighthouse README: `/path/to/lighthouse/README.md`
- Lighthouse issues: https://github.com/inspectioai/lighthouse/issues
- Harbor CLAUDE.md: `/path/to/harbor/CLAUDE.md`

## Next Steps

After migrating Harbor:
1. Consider using Lighthouse in Panorama for auth
2. Consider using Lighthouse in Faro for permissions
3. Update other Inspectio services to use Lighthouse
