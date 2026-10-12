"""Recipe registry and framework detection."""

from appsec_mcp.models.system_map import SystemGraph
from appsec_mcp.recipes.common import Recipe
from appsec_mcp.recipes.csrf import CsrfRecipe
from appsec_mcp.recipes.env_secrets import EnvSecretsRecipe
from appsec_mcp.recipes.input_validation import InputValidationRecipe
from appsec_mcp.recipes.rate_limit import RateLimitRecipe
from appsec_mcp.recipes.security_headers import SecurityHeadersRecipe

RECIPES: dict[str, Recipe] = {
    recipe.id: recipe
    for recipe in (
        SecurityHeadersRecipe(),
        RateLimitRecipe(),
        CsrfRecipe(),
        EnvSecretsRecipe(),
        InputValidationRecipe(),
    )
}

_DEPENDENCY_FRAMEWORKS = {
    "express@": "express",
    "next@": "nextjs",
    "flask": "flask",
    "fastapi": "fastapi",
    "spring-boot": "spring",
}


def detect_frameworks(graph: SystemGraph) -> set[str]:
    """Frameworks seen in routes and dependencies of the system map."""
    found: set[str] = set()
    for node in graph.nodes:
        if node.kind == "route":
            found.update(node.meta.get("frameworks", []))
        elif node.kind == "dependency":
            label = node.label.lower()
            found.update(
                fw
                for marker, fw in _DEPENDENCY_FRAMEWORKS.items()
                if label.startswith(marker) or marker in label
            )
    return found
