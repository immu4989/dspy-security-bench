"""Bounded static dependency declarations, not an installer or build evaluator.

Do not import project modules, evaluate markers, expand environment variables,
fetch URLs, or invoke build backends. Unsupported dynamic inputs must not turn
partial evidence into an automatic framework selection.
"""

from __future__ import annotations

import ast
import configparser
import os
import re
import shlex
import stat
import sys
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import InvalidName, canonicalize_name

from dspy_security_bench.jsonio import read_regular_bytes

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 4_000_000
MAX_FILES = 32
MAX_DIRECTORY_ENTRIES = 4096
MAX_NODES = 20_000
MAX_DEPTH = 50
MAX_REQUIREMENT = 4096
MANIFESTS = {"pyproject.toml", "setup.cfg", "setup.py", "Pipfile", "requirements.txt"}


class DeclarationError(ValueError):
    """Fixed diagnostics only: dependency URLs and source values can be private."""


class UnsupportedDeclaration(DeclarationError):
    """Valid installer inputs whose names require code, I/O, or unsupported syntax."""


def _fail(reason: str) -> None:
    raise DeclarationError(f"framework detection: {reason}; review declarations or choose --framework explicitly") from None


def _unsupported(reason: str) -> None:
    raise UnsupportedDeclaration(f"framework detection: {reason}; choose --framework explicitly") from None


def _mapping(value) -> dict:
    if not isinstance(value, dict):
        _fail("expected a dependency table")
    return value


def _name(value) -> str:
    if not isinstance(value, str) or len(value) > MAX_REQUIREMENT:
        _fail("invalid bounded package name")
    return canonicalize_name(value, validate=True)


def _requirement(value) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_REQUIREMENT:
        _fail("invalid bounded requirement")
    return _name(Requirement(value).name)


def _requirements(values) -> set[str]:
    if not isinstance(values, list):
        _fail("expected a requirement list")
    return {_requirement(value) for value in values}


def _bounded_tree(value) -> None:
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            _fail("declaration structure exceeds limits")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, ast.AST):
            pending.extend((child, depth + 1) for child in ast.iter_child_nodes(item))


def _package_table(value, *, poetry: bool = False) -> set[str]:
    names = set()
    for name, declaration in _mapping(value).items():
        if poetry and name == "python":
            continue
        name = _name(name)
        # Names are declared keys, not inferred from URLs, constraints, or paths.
        declarations = declaration if poetry and isinstance(declaration, list) else [declaration]
        if not declarations or any(not isinstance(item, (str, dict)) for item in declarations):
            _fail("unsupported named dependency declaration")
        names.add(name)
    return names


def _pyproject(data: dict) -> set[str]:
    project = _mapping(data.get("project", {}))
    dynamic = project.get("dynamic", [])
    if not isinstance(dynamic, list) or any(not isinstance(item, str) for item in dynamic):
        _fail("invalid dynamic metadata declaration")
    if set(dynamic) & {"dependencies", "optional-dependencies"}:
        _unsupported("dynamic dependency metadata cannot be evaluated statically")
    names = _requirements(project.get("dependencies", []))
    for values in _mapping(project.get("optional-dependencies", {})).values():
        names.update(_requirements(values))

    groups, includes = {}, {}
    for key, values in _mapping(data.get("dependency-groups", {})).items():
        normalized = _name(key)
        if normalized in groups or not isinstance(values, list):
            _fail("invalid or duplicate normalized dependency group")
        groups[normalized], includes[normalized] = values, set()
        for value in values:
            if isinstance(value, str):
                names.add(_requirement(value))
            elif isinstance(value, dict) and set(value) == {"include-group"}:
                includes[normalized].add(_name(value["include-group"]))
            else:
                _fail("unsupported dependency group item")
    _check_graph(includes)

    poetry = _mapping(_mapping(data.get("tool", {})).get("poetry", {}))
    names.update(_package_table(poetry.get("dependencies", {}), poetry=True))
    names.update(_package_table(poetry.get("dev-dependencies", {}), poetry=True))
    for group in _mapping(poetry.get("group", {})).values():
        names.update(_package_table(_mapping(group).get("dependencies", {}), poetry=True))
    return names


def _check_graph(graph: dict) -> None:
    visited, active = set(), set()

    def visit(node):
        if node not in graph:
            _fail("included dependency group is missing")
        if node in active or len(active) >= MAX_DEPTH:
            _fail("dependency include cycle or depth limit")
        if node in visited:
            return
        active.add(node)
        for child in graph[node]:
            visit(child)
        active.remove(node)
        visited.add(node)

    for node in graph:
        visit(node)


def _setup_cfg(source: str) -> set[str]:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read_string(source)
    if parser.defaults():
        _fail("setup.cfg DEFAULT inheritance is not supported")
    values = []
    if parser.has_option("options", "install_requires"):
        values.append(parser.get("options", "install_requires"))
    if parser.has_section("options.extras_require"):
        values.extend(value for _, value in parser.items("options.extras_require"))
    names = set()
    for value in values:
        if value.strip().startswith(("file:", "attr:")):
            _unsupported("dynamic setup.cfg dependency metadata")
        names.update(_requirement(line.strip()) for line in value.splitlines()
                     if line.strip() and not line.lstrip().startswith("#"))
    return names


def _setup_py(source: str) -> set[str]:
    tree = ast.parse(source)
    _bounded_tree(tree)
    functions, modules = set(), set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in {"setuptools", "distutils.core"}:
            functions.update(alias.asname or alias.name for alias in node.names if alias.name == "setup")
        elif isinstance(node, ast.Import):
            modules.update(alias.asname or alias.name for alias in node.names
                           if alias.name in {"setuptools", "distutils.core"})

    names, found = set(), False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        matches = (isinstance(func, ast.Name) and func.id in functions
                   or isinstance(func, ast.Attribute) and func.attr == "setup"
                   and ast.unparse(func.value) in modules)
        if not matches:
            continue
        found = True
        if node.args or any(keyword.arg is None for keyword in node.keywords):
            _unsupported("dynamic setup.py arguments are not supported")
        if len({keyword.arg for keyword in node.keywords}) != len(node.keywords):
            _fail("duplicate setup.py keyword")
        for keyword in node.keywords:
            if keyword.arg not in {"install_requires", "extras_require"}:
                continue
            try:
                value = ast.literal_eval(keyword.value)
            except (ValueError, TypeError):
                _unsupported("setup.py dependency fields must be literals")
            if keyword.arg == "install_requires":
                names.update(_requirements(list(value) if isinstance(value, tuple) else value))
            else:
                for extra in _mapping(value).values():
                    names.update(_requirements(list(extra) if isinstance(extra, tuple) else extra))
    if not found:
        _unsupported("setup.py has no supported literal setup declaration")
    return names


def _local_include(parent: Path, text: str) -> Path:
    # Portable slash-only paths; no absolute paths, traversal, URLs, expansion,
    # or drive-qualified input. Ancestor links are checked again before reading.
    if (not text or not text.isprintable() or any(char in text for char in "\\:$%~")
            or text.startswith("/") or ".." in text.split("/")):
        _fail("requirements includes must stay inside the project")
    return parent / text


def _option(line: str) -> tuple[str, str | None]:
    parts = shlex.split(line)
    if not parts:
        _fail("invalid requirement option")
    key, separator, value = parts[0].partition("=")
    if not separator and key.startswith(("-r", "-c", "-e", "-i", "-f")) and not key.startswith("--") and len(key) > 2:
        key, value, separator = key[:2], key[2:], "="
    arguments = ([value] if separator else []) + parts[1:]
    if len(arguments) > 1:
        _fail("unsupported requirement option arguments")
    return key, arguments[0] if arguments else None


def _requirements_file(source: str, parent: Path) -> tuple[set[str], set[Path], set[Path]]:
    names, includes, constraints = set(), set(), set()
    # Join before removing comments, matching pip's documented order.
    source = re.sub(r"(?<!\\)\\\r?\n", "", source)
    for raw in source.splitlines():
        line = re.split(r"(?:^|\s+)#", raw, maxsplit=1)[0].strip()
        if not line:
            continue
        if len(line) > MAX_REQUIREMENT:
            _fail("requirement line exceeds limit")
        if line.startswith("-"):
            option, value = _option(line)
            if option in {"-r", "--requirement"} and value is not None:
                includes.add(_local_include(parent, value))
            elif option in {"-c", "--constraint"} and value is not None:
                # Never open constraints. Remember local candidates so wildcard
                # discovery does not promote a constraint-only file to an install.
                try:
                    constraints.add(_local_include(parent, value))
                except DeclarationError:
                    pass
            elif option in {"-e", "--editable"} and value is not None:
                names.add(_install_requirement(value))
            elif option in {"-i", "--index-url", "--extra-index-url", "-f", "--find-links",
                            "--trusted-host", "--no-binary", "--only-binary", "--use-feature"} and value is not None:
                pass  # Installer configuration is not a dependency declaration.
            elif option in {"--no-index", "--prefer-binary", "--require-hashes", "--no-require-hashes",
                            "--pre", "--all-releases", "--only-final"} and value is None:
                pass
            else:
                _fail("unsupported requirement option")
        else:
            chunks = re.split(r"\s+(?=--)", line)
            names.add(_install_requirement(chunks[0]))
            for chunk in chunks[1:]:
                option, value = _option(chunk)
                if option not in {"--hash", "--config-settings"} or not value:
                    _fail("unsupported per-requirement option")
    return names, includes, constraints


def _install_requirement(value: str) -> str:
    if (value in {".", ".."} or value.startswith(("./", "../", "/", "~", "git+", "hg+", "svn+", "bzr+"))
            or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value)
            or ("@" not in value and value.endswith((".whl", ".zip", ".tar.gz")))):
        _unsupported("unnamed path, archive, or VCS requirements need explicit selection")
    return _requirement(value)


def _manifest_dependencies(path: Path, source: str) -> set[str]:
    if path.name in {"pyproject.toml", "Pipfile"}:
        data = tomllib.loads(source)
        _bounded_tree(data)
        if path.name == "pyproject.toml":
            return _pyproject(data)
        names = set()
        for key, value in data.items():
            if key not in {"source", "requires", "scripts", "pipenv"}:
                names.update(_package_table(value))
        return names
    if path.name == "setup.cfg":
        return _setup_cfg(source)
    return _setup_py(source)


class _Reader:
    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)
        self.sources: dict[Path, str] = {}
        self.total = 0

    def read(self, relative: Path) -> str:
        if relative in self.sources:
            return self.sources[relative]
        if len(self.sources) >= MAX_FILES:
            _fail("dependency file count exceeds limit")
        path = self.root
        for part in relative.parts:
            path /= part
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
                _fail("linked dependency input is not allowed")
        raw = read_regular_bytes(path, min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - self.total))
        if len(raw) > MAX_FILE_BYTES or self.total + len(raw) > MAX_TOTAL_BYTES:
            _fail("dependency byte budget exceeded")
        self.total += len(raw)
        self.sources[relative] = raw.decode("utf-8")
        return self.sources[relative]


def declared_dependencies(root: Path) -> dict[str, set[str]]:
    """Return normalized declared names and relative source files, or fail closed.

    Markers/extras are not evaluated; optional/dev declarations all participate.
    Stable owner-controlled files are required. Bounds and link checks are not
    a filesystem race sandbox or a validation of complete installer semantics.
    """
    try:
        reader = _Reader(root)
        candidates = set()
        with os.scandir(reader.root) as entries:
            for count, entry in enumerate(entries, 1):
                if count > MAX_DIRECTORY_ENTRIES:
                    _fail("project directory entry count exceeds limit")
                if entry.name in MANIFESTS or re.fullmatch(r"requirements-.+\.txt", entry.name):
                    candidates.add(Path(entry.name))
        evidence: dict[str, set[str]] = {}

        def add(names, path):
            for name in names:
                evidence.setdefault(name, set()).add(path.as_posix())

        req_roots, req_files, constraint_paths = set(), {}, set()
        unsupported = []

        def read_requirements(path, active):
            if path in active or len(active) >= MAX_DEPTH:
                _fail("requirements include cycle or depth limit")
            if path in req_files:
                return
            names, includes, constraints = _requirements_file(reader.read(path), path.parent)
            req_files[path] = (names, includes)
            constraint_paths.update(constraints)
            for child in sorted(includes):
                read_requirements(child, active | {path})

        for path in sorted(candidates):
            try:
                if path.suffix == ".txt":
                    req_roots.add(path)
                    read_requirements(path, set())
                else:
                    add(_manifest_dependencies(path, reader.read(path)), path)
            except UnsupportedDeclaration as exc:
                # Still inspect the other candidate files: unsupported metadata
                # must not hide an invalid input elsewhere or return a partial list.
                unsupported.append(exc)

        if unsupported:
            raise unsupported[0]

        pending, visited = list(req_roots - constraint_paths), set()
        while pending:
            path = pending.pop()
            if path in visited:
                continue
            visited.add(path)
            names, includes = req_files[path]
            add(names, path)
            pending.extend(includes)
        return evidence
    except DeclarationError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, SyntaxError, RecursionError,
            configparser.Error, InvalidRequirement, InvalidName):
        _fail("invalid, unreadable, or unsupported dependency input (source details withheld)")
