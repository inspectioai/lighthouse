"""Email templates for Lighthouse identity provider."""

from pathlib import Path

_TEMPLATES_DIR = Path(__file__).parent


def load_template(name: str) -> str:
    """Load an email template by name.

    Args:
        name: Template name without extension (e.g., "invitation_email")

    Returns:
        Template content as string

    Raises:
        FileNotFoundError: If template doesn't exist
    """
    template_path = _TEMPLATES_DIR / f"{name}.html"
    return template_path.read_text(encoding="utf-8")


def get_invitation_email_template() -> str:
    """Get the HTML invitation email template."""
    return load_template("invitation_email")


def get_verification_email_template() -> str:
    """Get the HTML verification email template."""
    return load_template("verification_email")
