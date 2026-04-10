from urllib.parse import urlparse, urlunparse


def url_path_join(*pieces):
    """Join components of a URL path while preserving edge slashes."""

    initial = pieces[0].startswith("/")
    final = pieces[-1].endswith("/")
    stripped = [s.strip("/") for s in pieces]
    result = "/".join(s for s in stripped if s)

    if initial:
        result = "/" + result
    if final:
        result = result + "/"
    if result == "//":
        result = "/"

    return result


def validate_absolute_http_url(url, label="url"):
    """Validate that a value is an absolute http(s) URL."""

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(
            f"{label} must be an absolute http(s) URL, got {url!r}."
        )
    return parsed


def normalize_public_base_url(base_url):
    """Normalize a public base URL for stable path joining."""

    parsed = validate_absolute_http_url(base_url, label="public_base_url")
    if parsed.params or parsed.query or parsed.fragment:
        raise ValueError(
            "public_base_url cannot include params, query, or fragment."
        )

    normalized_path = parsed.path.rstrip("/")
    if parsed.path == "/":
        normalized_path = ""

    return urlunparse(
        parsed._replace(
            path=normalized_path,
            params="",
            query="",
            fragment="",
        )
    )


def public_url_join(base_url, *pieces):
    """Join a normalized public base URL to one or more path segments."""

    parsed = urlparse(normalize_public_base_url(base_url))
    joined_path = url_path_join(parsed.path or "/", *pieces)
    return urlunparse(
        parsed._replace(path=joined_path, params="", query="", fragment="")
    )
