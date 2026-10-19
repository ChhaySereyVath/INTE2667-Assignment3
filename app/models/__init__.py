"""Import every model here so db.create_all() creates its table."""
from app.models import auth_models, enrollment_models, user  # noqa: F401
from app.models import election_models, voting_models  # noqa: F401  (Yufei: R16-R18)
from app.models import audit_models  # noqa: F401  (Keane: R13-R15, R19)
