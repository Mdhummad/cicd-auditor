"""
Repo ingestion module — clones a GitHub repo and extracts
all security-relevant files as structured objects.
"""

import os
import tempfile
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional
import git
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

SECURITY_RELEVANT_EXTENSIONS = {
    '.yml', '.yaml', '.json', '.env', '.sh', '.bash',
    '.py', '.js', '.ts', '.rb', '.go', '.java', '.tf',
    '.toml', '.ini', '.cfg', '.conf', '.config', '.xml',
    '.properties', '.secrets', '.key', '.pem', '.md'
}

SECURITY_RELEVANT_FILENAMES = {
    'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
    'Jenkinsfile', '.travis.yml', 'circle.yml', '.circleci/config.yml',
    'bitbucket-pipelines.yml', 'azure-pipelines.yml', 'cloudbuild.yaml',
    '.npmrc', '.pypirc', 'Makefile', 'makefile',
    'requirements.txt', 'package.json', 'package-lock.json',
    'Pipfile', 'Pipfile.lock', 'poetry.lock', 'go.mod', 'go.sum',
    'Gemfile', 'Gemfile.lock', 'composer.json',
}

# Paths to always skip
SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv', 'venv',
    '.env_dir', 'vendor', 'dist', 'build', '.tox', '.mypy_cache'
}


@dataclass
class RepoFile:
    """Represents a single extracted file from the repository."""
    path: str               # Relative path from repo root
    abs_path: str           # Absolute path on disk
    content: str            # File text content
    file_type: str          # Extension or filename (e.g. '.yml', 'Dockerfile')
    size_bytes: int = 0
    is_workflow: bool = False
    is_env_file: bool = False
    is_dockerfile: bool = False
    is_dependency_manifest: bool = False


@dataclass
class IngestedRepo:
    """Represents the result of cloning and walking a repository."""
    url: str
    owner: str
    repo_name: str
    tmp_dir: str
    files: List[RepoFile] = field(default_factory=list)
    clone_error: Optional[str] = None

    @property
    def workflow_files(self) -> List[RepoFile]:
        return [f for f in self.files if f.is_workflow]

    @property
    def env_files(self) -> List[RepoFile]:
        return [f for f in self.files if f.is_env_file]

    @property
    def dockerfiles(self) -> List[RepoFile]:
        return [f for f in self.files if f.is_dockerfile]

    @property
    def dependency_manifests(self) -> List[RepoFile]:
        return [f for f in self.files if f.is_dependency_manifest]

    def cleanup(self):
        """Remove the temporary clone directory."""
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)


def _parse_owner_repo(url: str):
    """Extract owner and repo name from a GitHub URL."""
    url = url.rstrip('/')
    parts = url.split('/')
    try:
        repo_name = parts[-1].replace('.git', '')
        owner = parts[-2]
        return owner, repo_name
    except IndexError:
        return 'unknown', 'unknown'


def _classify_file(rel_path: str, filename: str) -> dict:
    """Determine what category a file belongs to."""
    rel_lower = rel_path.replace('\\', '/')
    return {
        'is_workflow': '.github/workflows/' in rel_lower and filename.endswith(('.yml', '.yaml')),
        'is_env_file': filename.startswith('.env') or filename in ('secrets.yml', 'secrets.yaml', '.secrets'),
        'is_dockerfile': filename in ('Dockerfile', 'dockerfile') or filename.startswith('Dockerfile.'),
        'is_dependency_manifest': filename in (
            'requirements.txt', 'package.json', 'Pipfile',
            'pyproject.toml', 'setup.cfg', 'setup.py',
            'Gemfile', 'go.mod', 'composer.json', 'pom.xml'
        ),
    }


def clone_and_extract(repo_url: str, depth: int = 1) -> IngestedRepo:
    """
    Clone a GitHub repository (shallow) and extract all
    security-relevant files.

    Args:
        repo_url: Full GitHub URL (https://github.com/owner/repo)
        depth:    Shallow clone depth (1 = latest commit only)

    Returns:
        IngestedRepo object with all extracted files.
    """
    owner, repo_name = _parse_owner_repo(repo_url)
    tmp_dir = tempfile.mkdtemp(prefix=f"cicd_audit_{repo_name}_")

    result = IngestedRepo(
        url=repo_url,
        owner=owner,
        repo_name=repo_name,
        tmp_dir=tmp_dir,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"Cloning {owner}/{repo_name}…", total=None)

        try:
            git.Repo.clone_from(
                repo_url,
                tmp_dir,
                depth=depth,
                no_single_branch=False,
            )
        except git.exc.GitCommandError as e:
            result.clone_error = str(e)
            console.print(f"[bold red]✗ Clone failed:[/] {e}")
            return result

        progress.update(task, description=f"Walking file tree…")

        root_path = Path(tmp_dir)
        files_found = 0

        for item in root_path.rglob('*'):
            if not item.is_file():
                continue

            # Skip unwanted directories
            if any(skip in item.parts for skip in SKIP_DIRS):
                continue

            filename = item.name
            ext = item.suffix.lower()
            rel_path = str(item.relative_to(root_path))

            # Decide if this file is security-relevant
            is_relevant = (
                ext in SECURITY_RELEVANT_EXTENSIONS
                or filename in SECURITY_RELEVANT_FILENAMES
                or filename.startswith('.env')
                or 'Dockerfile' in filename
            )

            if not is_relevant:
                continue

            try:
                content = item.read_text(errors='ignore', encoding='utf-8')
            except Exception:
                content = ''

            classification = _classify_file(rel_path, filename)

            repo_file = RepoFile(
                path=rel_path,
                abs_path=str(item),
                content=content,
                file_type=ext if ext else filename,
                size_bytes=item.stat().st_size,
                **classification,
            )
            result.files.append(repo_file)
            files_found += 1

        progress.update(task, description=f"Extracted {files_found} files")

    console.print(
        f"[bold green]✓[/] Cloned [cyan]{owner}/{repo_name}[/] → "
        f"[dim]{files_found} files extracted[/]"
    )
    return result
