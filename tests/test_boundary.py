"""Guards that keep the project publishable via `git subtree split` and safe by construction."""
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# The package must never import anything that can deserialise or load a model.
FORBIDDEN_IMPORTS = {"pickle", "_pickle", "cPickle", "dill", "joblib", "torch", "numpy", "keras"}

# Homelab context that must not leak into the published project.
FORBIDDEN_TEXT = ["inventory/", "secrets/", "infra/", "192.168.", "labctl", "lab-platform"]


def shipped_files():
    for path in ROOT.rglob("*"):
        parts = path.relative_to(ROOT).parts
        if path.is_file() and parts[0] != "tests" and not any(
            p.startswith(".") or p == "__pycache__" for p in parts
        ):
            yield path


def test_package_never_imports_a_deserialiser():
    for path in (ROOT / "src").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module or ""]
            else:
                continue
            for name in names:
                assert name.split(".")[0] not in FORBIDDEN_IMPORTS, f"{path}: imports {name}"


def imported_modules():
    """Every absolute import in the package, as (file, dotted name)."""
    for path in (ROOT / "src").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module or ""]
            else:
                continue  # a relative import is this package by definition
            for name in names:
                if name:
                    yield path, name


# The single authorised exception (ADR 0012): the semantic-retrieval backend, in the
# one module that is allowed to touch it. Scoped to a path rather than added to the
# allowlist, so an `import onnxruntime` anywhere else still fails.
EXTRA_IMPORTS = {"src/modelwarden/scanners/rag/embedding.py": {"onnxruntime"}}


def test_package_imports_nothing_but_the_standard_library():
    """The loudest claim this project makes, enforced rather than believed.

    "No dependency outside the standard library" appears in the README, the ADR, the
    changelog and the write-up. Until now the only guard was a denylist of six
    deserialisers, which would not have noticed `requests` or `pydantic` arriving.
    An allowlist notices anything.

    Note what this walk really covers: `ast.walk` visits every node, so an import
    inside a function is caught exactly like one at the top of the file. ADR 0012
    assumed otherwise when it decided the backend would be imported lazily, and the
    decision survives only because the exception below is written down.
    """
    allowed = set(sys.stdlib_module_names) | {"modelwarden"}
    foreign = {
        (str(path.relative_to(ROOT)), name)
        for path, name in imported_modules()
        if name.split(".")[0] not in allowed
        and name.split(".")[0] not in EXTRA_IMPORTS.get(str(path.relative_to(ROOT)), set())
    }
    assert not foreign, f"imports from outside the standard library: {sorted(foreign)}"


def test_the_backend_stays_in_the_one_module_allowed_to_have_it():
    """An exception that spreads is not an exception any more.

    `pip install modelwarden` must stay standard-library-only, which holds only while
    nothing on an ordinary code path reaches the backend. Two things are checked: no
    other file imports it, and no scanner imports `embedding` at module level — an
    import at the top of a scanner runs on registry import, so the extra would become
    mandatory without anyone declaring it.
    """
    backend = "onnxruntime"
    strays = {
        str(path.relative_to(ROOT))
        for path, name in imported_modules()
        if name.split(".")[0] == backend
        and backend not in EXTRA_IMPORTS.get(str(path.relative_to(ROOT)), set())
    }
    assert not strays, f"{backend} imported outside the authorised module: {sorted(strays)}"

    for path in (ROOT / "src").rglob("*.py"):
        if path.name == "embedding.py":
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in tree.body:  # module level only; a lazy import inside a function is fine
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module or ""]
            assert not any(name.endswith("rag.embedding") for name in names), (
                f"{path.relative_to(ROOT)} imports the embedding backend at module level"
            )


def test_the_manifest_promises_no_runtime_dependency():
    """The other half of the same claim: what `pip install modelwarden` pulls in.

    The import guard above catches code reaching for a package. This catches a
    manifest that declares one before any code uses it, which the import walk cannot
    see at all: a dependency listed here and never imported still arrives on every
    machine that installs the tool. The `dev` extra is tooling for working on the
    project, not something a user of the tool receives.

    (An earlier version of this docstring claimed a lazily imported dependency would
    satisfy the first check. It would not — that walk is an `ast.walk`, which reaches
    inside functions. The two tests overlap more than the note suggested.)
    """
    import tomllib

    manifest = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = manifest["project"]
    assert project["dependencies"] == [], f"runtime dependencies: {project['dependencies']}"
    # `dev` is tooling for working on the project; `rag` is the semantic-retrieval
    # backend authorised by ADR 0012, which is why the core list above stays empty.
    # An extra nobody recorded in an ADR still fails here.
    allowed = {"dev", "rag"}
    extras = set(project.get("optional-dependencies", {}))
    assert extras <= allowed, f"undeclared extras: {sorted(extras - allowed)}"


def test_no_homelab_references():
    for path in shipped_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for needle in FORBIDDEN_TEXT:
            assert needle not in text, f"{path.relative_to(ROOT)} mentions {needle!r}"


def test_every_relative_link_resolves_inside_the_published_tree():
    """A link that works here and dies after `subtree split` is still a broken link.

    The guard above greps for text that must not be published. This catches the
    opposite mistake: text that refers to something which simply is not there once the
    project is split out. The ADRs are the standing trap — they live in the repository
    this project is developed in, `docs/` does not travel with the subtree, and a
    relative link to one resolves perfectly on a developer's machine and 404s for
    everybody else. Naming them in prose is the fix; this test is what notices when
    somebody links one again.
    """
    link = re.compile(r"\]\((?!https?://|#|mailto:)([^)\s]+)\)")
    broken = []
    for path in shipped_files():
        if path.suffix != ".md":
            continue
        for target in link.findall(path.read_text(encoding="utf-8", errors="ignore")):
            resolved = (path.parent / target.split("#", 1)[0]).resolve()
            if not resolved.exists():
                broken.append(f"{path.relative_to(ROOT)} -> {target}")
    assert not broken, f"links that break once published: {sorted(broken)}"
