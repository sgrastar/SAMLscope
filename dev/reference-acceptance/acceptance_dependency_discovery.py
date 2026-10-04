"""Reuse dependency discovery within one explicit generation, never verification.

Archived production JARs and evidence are checked by each caller as before. Outside
``dependency_discovery_scope`` every request runs Gradle afresh. A changed Gradle
input or dependency file invalidates a scoped entry instead of silently refreshing it.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


_SCOPE = ContextVar("acceptance_dependency_discovery", default=None)
_EXCLUDED = {".git", ".gradle", "build", "node_modules", ".venv", "private"}
_ENVIRONMENT = ("JAVA_HOME", "GRADLE_USER_HOME", "GRADLE_OPTS", "JAVA_OPTS",
                "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "PATH")


@contextmanager
def dependency_discovery_scope():
    """Own a fresh, exception-safe discovery map for this generation only."""
    token = _SCOPE.set({})
    try:
        yield
    finally:
        _SCOPE.reset(token)


def _file_stat(path):
    try:
        value = path.lstat()
    except FileNotFoundError:
        return None
    result = (value.st_dev, value.st_ino, value.st_mode, value.st_size,
              value.st_mtime_ns, value.st_ctime_ns)
    if stat.S_ISLNK(value.st_mode):
        return result, os.readlink(path), _file_stat(path.resolve())
    return result


def _input_snapshot(repository):
    files = []
    for directory, children, names in os.walk(repository, followlinks=False):
        children[:] = sorted(n for n in children if n not in _EXCLUDED)
        for name in sorted(names):
            path = Path(directory) / name
            if (name.endswith((".gradle", ".gradle.kts", ".lockfile"))
                    or name in {"gradle.properties", "gradlew", "gradlew.bat"}
                    or path.parent == repository / "gradle" and name.endswith(".toml")
                    or path.parent == repository / "gradle/wrapper"):
                if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
                    raise ValueError("Unsupported dependency discovery input")
                files.append((str(path.relative_to(repository)), _file_stat(path),
                              hashlib.sha256(path.read_bytes()).hexdigest()))
    user_home = Path(os.environ.get("GRADLE_USER_HOME", Path.home() / ".gradle")).resolve()
    user_inputs = [user_home / name for name in ("gradle.properties", "init.gradle", "init.gradle.kts")]
    init_directory = user_home / "init.d"
    if init_directory.exists():
        if not init_directory.is_dir():
            raise ValueError("Unsupported Gradle initialization input")
        user_inputs.extend(sorted(path for path in init_directory.iterdir()
                                  if path.name.endswith((".gradle", ".gradle.kts"))))
    user_files = [(str(init_directory), _file_stat(init_directory), None)]
    for path in user_inputs:
        value = _file_stat(path)
        if value is None:
            user_files.append((str(path), None, None))
        else:
            if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("Unsupported Gradle initialization input")
            user_files.append((str(path), value, hashlib.sha256(path.read_bytes()).hexdigest()))
    # No environment values are persisted or included in error messages.
    environment = tuple((name, os.environ.get(name)) for name in _ENVIRONMENT)
    environment += tuple(sorted((name, value) for name, value in os.environ.items()
                                if name.startswith("ORG_GRADLE_PROJECT_")))
    # User properties/init script bytes and environment values stay in memory only.
    return tuple(files), tuple(user_files), environment


def _dependency_snapshot(classpath):
    entries = classpath.split(os.pathsep)
    if not entries or any(not value or not Path(value).is_absolute() for value in entries):
        raise ValueError("Invalid discovered dependency classpath")
    result = []
    for value in entries:
        path = Path(value)
        if path.exists() and not path.is_file():
            raise ValueError("Dependency discovery requires file classpath entries")
        result.append((value, str(path.resolve()), _file_stat(path)))
    return tuple(result)


def _discover(repository, project, configuration):
    with tempfile.TemporaryDirectory(prefix="samlscope-dependency-discovery-") as temporary:
        init = Path(temporary) / "classpath.gradle"
        init.write_text('''gradle.projectsEvaluated {
  def p = gradle.rootProject.project("%s")
  p.tasks.register("printAcceptanceDependencyClasspath") {
    doLast { println(p.configurations.getByName("%s").asPath) }
  }
}
''' % (project, configuration))
        task = project + ":printAcceptanceDependencyClasspath"
        result = subprocess.run([str(repository / "gradlew"), "-q", "-I", str(init), task],
                                cwd=repository, capture_output=True, text=True,
                                check=True, timeout=60)
        value = result.stdout.strip()
        if not value:
            raise ValueError("Missing dependency classpath")
        return value


@dataclass(frozen=True)
class _Discovered:
    classpath: str
    inputs: tuple
    dependencies: tuple


def runtime_classpath(repository, project=":runner", configuration="runtimeClasspath"):
    """Discover only path dependencies; callers still execute every evidence replay."""
    repository = Path(repository).resolve(strict=True)
    if (not re.fullmatch(r"(?::[A-Za-z][A-Za-z0-9_-]*)+", project)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", configuration)):
        raise ValueError("Invalid dependency discovery configuration")
    key = repository, project, configuration
    inputs = _input_snapshot(repository)
    scope = _SCOPE.get()
    if scope is not None and key in scope:
        previous = scope[key]
        if inputs != previous.inputs:
            raise ValueError("Dependency discovery inputs changed within generation")
        if _dependency_snapshot(previous.classpath) != previous.dependencies:
            raise ValueError("Dependency files changed within generation")
        return previous.classpath
    value = _discover(repository, project, configuration)
    if inputs != _input_snapshot(repository):
        raise ValueError("Dependency discovery inputs changed during discovery")
    dependencies = _dependency_snapshot(value)
    if scope is not None:
        scope[key] = _Discovered(value, inputs, dependencies)
    return value
