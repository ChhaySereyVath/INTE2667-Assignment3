"""Import every model here so db.create_all() creates its table."""
from app.models import auth_models, user  # noqa: F401