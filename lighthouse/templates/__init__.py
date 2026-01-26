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


def get_invitation_email_template(
    tenant_name: str = "Inspectio.ai",
    panorama_url: str = "https://panorama.app.inspectio.ai",
) -> str:
    """Get the HTML invitation email template with dynamic values.

    Args:
        tenant_name: Name of the tenant to display in the email
        panorama_url: URL to the Panorama login page

    Returns:
        Template content with placeholders replaced
    """
    from urllib.parse import urlencode

    template = load_template("invitation_email")

    # Add tenant name as query parameter to Panorama URL
    separator = "&" if "?" in panorama_url else "?"
    query_params = urlencode({"tenantname": tenant_name})
    panorama_url_with_tenant = f"{panorama_url}{separator}{query_params}"

    # Replace custom placeholders (Cognito will replace {username} and {####})
    template = template.replace("{{TENANT_NAME}}", tenant_name)
    template = template.replace("{{PANORAMA_URL}}", panorama_url_with_tenant)
    return template


def get_verification_email_template() -> str:
    """Get the HTML verification email template."""
    return load_template("verification_email")
