from importlib.metadata import requires
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[1]
IGNORED_PARTS = {
    ".git",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
}
ALLOWED_FILES = {
    ".gitattributes",
    ".github/workflows/ci.yml",
    ".gitignore",
    ".python-version",
    "CHANGELOG.md",
    "LICENSE",
    "PROVENANCE.md",
    "README.md",
    "SECURITY.md",
    "pyproject.toml",
    "uv.lock",
    "src/totp_batch/__init__.py",
    "src/totp_batch/__main__.py",
    "src/totp_batch/cli.py",
    "src/totp_batch/core.py",
    "src/totp_batch/input.py",
    "src/totp_batch/model.py",
    "tests/test_base32.py",
    "tests/test_cli.py",
    "tests/test_core.py",
    "tests/test_input.py",
    "tests/test_module.py",
    "tests/test_output.py",
    "tests/test_repository.py",
}
SDIST_FILES = {
    ".gitattributes",
    ".github/workflows/ci.yml",
    ".gitignore",
    ".python-version",
    "CHANGELOG.md",
    "LICENSE",
    "PROVENANCE.md",
    "README.md",
    "SECURITY.md",
    "pyproject.toml",
    "src/totp_batch",
    "tests",
    "uv.lock",
}


def test_runtime_dependencies_are_empty() -> None:
    assert requires("totp-batch") is None


def test_repository_contains_only_allowlisted_files() -> None:
    files = {
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in PROJECT_ROOT.rglob("*")
        if path.is_file() and not IGNORED_PARTS.intersection(path.parts)
    }
    assert files == ALLOWED_FILES


def test_build_configuration_has_explicit_archive_allowlists() -> None:
    configuration = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    sdist = configuration.split("[tool.hatch.build.targets.sdist]", maxsplit=1)[1]
    sdist = sdist.split("\n[", maxsplit=1)[0]
    includes = {
        line.strip().strip('",').removeprefix("/")
        for line in sdist.splitlines()
        if line.strip().startswith('"/')
    }
    assert "dependencies = []" in configuration
    assert 'packages = ["src/totp_batch"]' in configuration
    assert includes == SDIST_FILES


def test_repository_has_no_private_artifacts() -> None:
    forbidden_names = {
        ".env",
        "id_rsa",
        "id_ed25519",
        "credentials.json",
        "secrets.json",
    }
    forbidden_suffixes = {".key", ".pem", ".pfx", ".p12"}
    files = [path for path in PROJECT_ROOT.rglob("*") if path.is_file()]
    assert not [
        path
        for path in files
        if path.name.lower() in forbidden_names
        or path.suffix.lower() in forbidden_suffixes
    ]


def test_repository_text_has_no_private_paths_or_secret_markers() -> None:
    private_markers = (
        "-----BEGIN " + "PRIVATE KEY-----",
        "C:" + "\\Users\\",
        "C:/" + "Users/",
        "/" + "home/",
        "/" + "Users/",
    )
    findings: dict[str, list[str]] = {}
    for relative_path in ALLOWED_FILES:
        text = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
        matches = [marker for marker in private_markers if marker in text]
        if matches:
            findings[relative_path] = matches
    assert findings == {}


def test_python_files_stay_within_250_pure_lines() -> None:
    oversized: dict[str, int] = {}
    for path in PROJECT_ROOT.rglob("*.py"):
        if IGNORED_PARTS.intersection(path.parts):
            continue
        pure_lines = sum(
            bool(line.strip()) and not line.lstrip().startswith("#")
            for line in path.read_text(encoding="utf-8").splitlines()
        )
        if pure_lines > 250:
            oversized[path.relative_to(PROJECT_ROOT).as_posix()] = pure_lines
    assert oversized == {}


def test_docs_expose_security_and_publication_boundaries() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    security = (PROJECT_ROOT / "SECURITY.md").read_text(encoding="utf-8")
    provenance = (PROJECT_ROOT / "PROVENANCE.md").read_text(encoding="utf-8")
    assert "## Publication boundary" in readme
    assert "totp-batch/input/v1" in readme
    assert "totp-batch/output/v1" in readme
    assert "/security/advisories/new" in security
    assert "## Publication boundary" in provenance
