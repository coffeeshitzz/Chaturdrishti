import httpx
import asyncio
import base64
import re
import math
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from loguru import logger
from typing import List, Dict, Tuple, Optional
from dotenv import load_dotenv
from graph.schema import Signal, SourceType, Entity, SensitivityLevel

load_dotenv()


# ── Secret regex patterns ─────────────────────────────────────────────────
# Each entry: (pattern_name, compiled_regex, sensitivity)
SECRET_REGEXES = [
    # AWS
    ("AWS_ACCESS_KEY",
     re.compile(r'AKIA[0-9A-Z]{16}'),
     "critical"),
    ("AWS_SECRET_KEY",
     re.compile(r'(?i)aws.{0,20}secret.{0,20}[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
     "critical"),

    # Generic API keys
    ("API_KEY_ASSIGNMENT",
     re.compile(r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'),
     "critical"),

    # Passwords
    ("PASSWORD_ASSIGNMENT",
     re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?'),
     "critical"),

    # Tokens
    ("TOKEN_ASSIGNMENT",
     re.compile(r'(?i)(token|secret_key|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?'),
     "critical"),

    # Private keys
    ("PRIVATE_KEY",
     re.compile(r'-----BEGIN [A-Z]+ PRIVATE KEY-----'),
     "critical"),

    # Connection strings
    ("DATABASE_URL",
     re.compile(r'(?i)(database_url|db_url|connection_string)\s*[=:]\s*["\']?(\w+://[^\s"\']+)["\']?'),
     "critical"),
    ("MONGODB_URI",
     re.compile(r'mongodb(\+srv)?://[^\s"\']+'),
     "critical"),
    ("POSTGRES_URI",
     re.compile(r'postgresql?://[^\s"\']+'),
     "critical"),
    ("REDIS_URI",
     re.compile(r'redis://[^\s"\']+'),
     "critical"),

    # GitHub tokens
    ("GITHUB_TOKEN",
     re.compile(r'gh[pousr]_[A-Za-z0-9]{36}'),
     "critical"),

    # Stripe
    ("STRIPE_KEY",
     re.compile(r'sk_(live|test)_[A-Za-z0-9]{24,}'),
     "critical"),

    # Slack
    ("SLACK_TOKEN",
     re.compile(r'xox[baprs]-[A-Za-z0-9\-]+'),
     "critical"),

    # Generic high-entropy strings assigned to sensitive vars
    ("SECRET_ASSIGNMENT",
     re.compile(r'(?i)(secret|private_key|signing_key)\s*[=:]\s*["\']?([A-Za-z0-9+/=_\-]{32,})["\']?'),
     "high"),

    # Internal hostnames in configs
    ("INTERNAL_HOSTNAME",
     re.compile(r'(?i)(host|hostname|endpoint|url)\s*[=:]\s*["\']?([\w\-]+\.(internal|corp|local|intranet|private)[\w\.]*)["\']?'),
     "high"),

    # IP addresses in configs
    ("PRIVATE_IP",
     re.compile(r'(?i)(host|ip|endpoint)\s*[=:]\s*["\']?(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)["\']?'),
     "high"),

    # AWS region hints
    ("AWS_REGION",
     re.compile(r'(?i)(aws_region|region)\s*[=:]\s*["\']?(us-east-[12]|us-west-[12]|eu-west-[123]|ap-southeast-[12])["\']?'),
     "medium"),
]

# ── Placeholder values to skip ────────────────────────────────────────────
PLACEHOLDERS = {
    "changeme", "your_key_here", "your-key-here",
    "xxxx", "xxxxxx", "xxxxxxxx",
    "example", "placeholder", "todo",
    "insert_here", "replace_me", "your_token",
    "your_password", "your_secret", "enter_here",
    "abc123", "test", "testing", "password123",
    "secret", "mysecret", "mypassword",
    "", "null", "none", "undefined",
}

# ── Paths to skip ─────────────────────────────────────────────────────────
SKIP_PATHS = {
    "test/", "tests/", "spec/", "specs/",
    "docs/", "doc/", "documentation/",
    "examples/", "example/", "samples/", "sample/",
    "fixtures/", "mocks/", "mock/",
    "__pycache__/", "node_modules/", "vendor/",
    ".git/",
}

# ── File priority tiers ───────────────────────────────────────────────────
PRIORITY_1 = {
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.backup", ".env.bak",
    "secrets.yml", "secrets.yaml", "secrets.json",
    "credentials", "credentials.json", "credentials.yml",
    ".netrc", ".npmrc", ".pypirc",
}

PRIORITY_2_PATTERNS = [
    "docker-compose", "dockerfile",
    "config.py", "settings.py", "configuration.py",
    "database.yml", "database.yaml", "database.json",
    "values.yaml", "values.yml",         # Helm
    "terraform.tfvars", ".tfvars",
    "main.tf", "variables.tf",
    "jenkinsfile", "pipeline.yml",
    ".github/workflows",
    "serverless.yml", "serverless.yaml",
    "app.config", "web.config",
    "application.yml", "application.properties",
]

PRIORITY_3_PATTERNS = [
    "package.json", "requirements.txt",
    "gemfile", "pom.xml", "build.gradle",
    "go.mod", "cargo.toml",
    "makefile", "rakefile",
    "nginx.conf", "apache.conf",
    "supervisord.conf",
]

# ── Technology keywords ───────────────────────────────────────────────────
TECH_KEYWORDS = {
    "kubernetes": "KUBERNETES", "k8s": "KUBERNETES",
    "docker": "DOCKER", "terraform": "TERRAFORM",
    "ansible": "ANSIBLE", "helm": "HELM",
    "aws": "AWS", "gcp": "GCP", "azure": "AZURE",
    "s3": "AWS_S3", "ec2": "AWS_EC2",
    "lambda": "AWS_LAMBDA", "eks": "AWS_EKS",
    "postgresql": "POSTGRESQL", "postgres": "POSTGRESQL",
    "mysql": "MYSQL", "mongodb": "MONGODB",
    "redis": "REDIS", "elasticsearch": "ELASTICSEARCH",
    "cassandra": "CASSANDRA", "kafka": "KAFKA",
    "fastapi": "FASTAPI", "django": "DJANGO",
    "flask": "FLASK", "express": "EXPRESS",
    "react": "REACT", "nextjs": "NEXTJS",
    "jenkins": "JENKINS", "gitlab": "GITLAB_CI",
    "github actions": "GITHUB_ACTIONS",
    "datadog": "DATADOG", "grafana": "GRAFANA",
    "prometheus": "PROMETHEUS",
    "vault": "HASHICORP_VAULT",
    "consul": "HASHICORP_CONSUL",
    "istio": "ISTIO", "rabbitmq": "RABBITMQ",
    "nginx": "NGINX", "traefik": "TRAEFIK",
}


def _calculate_entropy(s: str) -> float:
    """Shannon entropy — high entropy = likely a real secret."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log(p, 2) for p in prob if p > 0)


def _is_placeholder(value: str) -> bool:
    """
    Check if a matched value looks like a placeholder, a code reference,
    or a template variable rather than a real secret.

    This is the primary false-positive gate for the GitHub secret scanner.
    A real secret is a high-entropy literal string. Everything else —
    function calls, variable references, template placeholders, type hints,
    docstring fragments — should be filtered here.
    """
    v = value.strip()
    v_lower = v.lower()

    # Known placeholder strings
    if v_lower in PLACEHOLDERS:
        return True

    # Too short to be a real secret
    if len(v) < 8:
        return True

    # Low entropy — probably not random
    if _calculate_entropy(v) < 2.5:
        return True

    # Variable references: ${VAR}, $(VAR), %VAR%, #{VAR}
    if v.startswith("${") or v.startswith("$(") or v.startswith("%"):
        return True
    if v.startswith("#{") and v.endswith("}"):
        return True

    # Code-shaped values: function calls, method calls, dictionary lookups
    # Catches: getenv(...), os.environ[...], config.get(...), etc.
    code_indicators = [
        "(", ")", "[", "]",       # function calls, dict lookups
        "getenv", "os.environ",   # Python env var access
        "process.env",            # Node.js env var access
        "config.", "Config.",     # config object access
        "vault.", "Vault.",       # vault secret access
        "secrets.", "Secrets.",   # secrets manager access
        "request.", "Request.",   # HTTP request object
        "import ", "require(",   # import statements
        "lambda", "def ",        # Python keywords
        "=>",                     # JS arrow functions
    ]
    if any(indicator in v for indicator in code_indicators):
        return True

    # Template placeholders: <your-password>, {{PASSWORD}}, %s, {0}
    if v.startswith("<") and v.endswith(">"):
        return True
    if "{{" in v and "}}" in v:
        return True

    # Pure identifier pattern: all lowercase letters and underscores,
    # no digits or special chars mixed in. Real secrets have entropy;
    # variable names like "database_password" don't.
    import re
    if re.match(r'^[a-z][a-z_]*$', v) and len(v) > 10:
        return True

    return False


def _should_skip_path(path: str) -> bool:
    """Check if a file path is in a directory we should skip."""
    p = path.lower()
    return any(skip in p for skip in SKIP_PATHS)


def _get_file_priority(filename: str) -> int:
    """
    Return priority score for a file.
    1 = highest priority, 3 = lower priority, 0 = not interesting.
    """
    name = filename.lower().split("/")[-1]
    full = filename.lower()

    if name in PRIORITY_1 or any(name.endswith(p) for p in PRIORITY_1):
        return 1

    if any(p in full for p in PRIORITY_2_PATTERNS):
        return 2

    if any(p in full for p in PRIORITY_3_PATTERNS):
        return 3

    # Any .env variant
    if ".env" in name:
        return 1

    return 0


class GitHubCollector:
    """
    Deep GitHub OSINT collector.
    Discovers repos, traverses file trees, reads file contents,
    and extracts secrets, infrastructure hints, and tech stack
    evidence using regex patterns and entropy analysis.
    """

    def __init__(self, target_org: str):
        self.target_org = target_org
        self.org_name   = target_org.split(".")[0]
        self.token      = os.getenv("GITHUB_TOKEN")
        self.headers    = {
            "Authorization": f"token {self.token}",
            "Accept":        "application/vnd.github.v3+json"
        }
        self.base_url    = "https://api.github.com"
        self.signals: List[Signal] = []
        self._api_calls  = 0
        self._max_calls  = 200   # conservative limit per run

    # ── Public entry point ────────────────────────────────────────────────

    async def collect(self) -> List[Signal]:
        logger.info(f"🔍 Starting GitHub deep scan for: {self.target_org}")

        async with httpx.AsyncClient(
            headers=self.headers, timeout=30.0
        ) as client:
            repos = await self._fetch_repos(client)

            if not repos:
                logger.warning(f"  No repos found for {self.org_name}")
                return self.signals

            logger.info(f"  Found {len(repos)} repos — scanning up to 15")

            for repo in repos[:15]:
                if self._api_calls >= self._max_calls:
                    logger.warning("  API call limit reached — stopping")
                    break
                await self._process_repo(client, repo)
                await asyncio.sleep(0.3)

        logger.success(
            f"✅ GitHub deep scan complete — "
            f"{len(self.signals)} signals, "
            f"{self._api_calls} API calls"
        )
        return self.signals

    # ── Repository discovery ──────────────────────────────────────────────

    async def _fetch_repos(self, client) -> list:
        for endpoint in [
            f"{self.base_url}/orgs/{self.org_name}/repos",
            f"{self.base_url}/users/{self.org_name}/repos",
        ]:
            try:
                r = await self._get(client, endpoint, {
                    "type": "public", "per_page": 30, "sort": "updated"
                })
                if r:
                    return r
            except Exception:
                continue
        return []

    # ── Repo processing ───────────────────────────────────────────────────

    async def _process_repo(self, client, repo: Dict):
        repo_full  = repo.get("full_name", "")
        repo_url   = repo.get("html_url", "")
        language   = repo.get("language", "") or ""
        description= repo.get("description", "") or ""
        topics     = repo.get("topics", [])

        logger.info(f"  📁 {repo_full}")

        # 1. Repo metadata signal
        self._add_repo_metadata_signal(repo)

        # 2. Get file tree and prioritise
        files = await self._get_file_tree(client, repo_full)
        if files:
            priority_files = self._prioritise_files(files)
            logger.info(
                f"     {len(files)} files total, "
                f"{len(priority_files)} selected for reading"
            )

            # 3. Read and scan each priority file
            for filepath, priority in priority_files[:20]:
                if self._api_calls >= self._max_calls:
                    break
                content = await self._read_file(client, repo_full, filepath)
                if content:
                    self._scan_file_contents(
                        content, filepath, repo_full, repo_url, priority
                    )
                await asyncio.sleep(0.2)

        # 4. Contributors
        await self._collect_contributors(client, repo_full, repo_url)

        # 5. Commit history scan
        await self._scan_commits(client, repo_full, repo_url)

    # ── File tree ─────────────────────────────────────────────────────────

    async def _get_file_tree(self, client, repo_full: str) -> List[str]:
        """Get flat list of all file paths using Git trees API."""
        try:
            # Get default branch
            repo_data = await self._get(
                client, f"{self.base_url}/repos/{repo_full}", {}
            )
            if not repo_data:
                return []
            branch = repo_data.get("default_branch", "main")

            # Get full tree recursively
            tree_data = await self._get(
                client,
                f"{self.base_url}/repos/{repo_full}/git/trees/{branch}",
                {"recursive": "1"}
            )
            if not tree_data:
                return []

            return [
                item["path"]
                for item in tree_data.get("tree", [])
                if item.get("type") == "blob"
                and not _should_skip_path(item["path"])
            ]

        except Exception as e:
            logger.debug(f"     Tree fetch failed: {e}")
            return []

    def _prioritise_files(
        self, files: List[str]
    ) -> List[Tuple[str, int]]:
        """
        Score and sort files by sensitivity priority.
        Returns (filepath, priority) sorted highest priority first.
        """
        scored = []
        for f in files:
            p = _get_file_priority(f)
            if p > 0:
                scored.append((f, p))

        # Sort: priority 1 first, then 2, then 3
        return sorted(scored, key=lambda x: x[1])

    # ── File reading ──────────────────────────────────────────────────────

    async def _read_file(
        self, client, repo_full: str, filepath: str
    ) -> Optional[str]:
        """Read and decode a file's contents."""
        try:
            data = await self._get(
                client,
                f"{self.base_url}/repos/{repo_full}/contents/{filepath}",
                {}
            )
            if not data or not isinstance(data, dict):
                return None

            # Skip large files
            if data.get("size", 0) > 100_000:
                logger.debug(f"     Skipping large file: {filepath}")
                return None

            encoding = data.get("encoding", "")
            content  = data.get("content", "")

            if encoding == "base64" and content:
                return base64.b64decode(
                    content.replace("\n", "")
                ).decode("utf-8", errors="ignore")

            return None

        except Exception:
            return None

    # ── Content scanning ──────────────────────────────────────────────────

    def _scan_file_contents(
        self,
        content: str,
        filepath: str,
        repo_full: str,
        repo_url: str,
        priority: int
    ):
        """
        Run all extractors against file content.
        Each extractor produces zero or more signals.
        """
        self._extract_secrets(content, filepath, repo_full, repo_url)
        self._extract_infrastructure(content, filepath, repo_full, repo_url)
        self._extract_tech_stack(content, filepath, repo_full, repo_url)

        # Special parsers for known file types
        fname = filepath.lower().split("/")[-1]
        if "dockerfile" in fname:
            self._parse_dockerfile(content, filepath, repo_full, repo_url)
        elif "docker-compose" in fname:
            self._parse_docker_compose(content, filepath, repo_full, repo_url)
        elif fname.endswith((".tf", ".tfvars")):
            self._parse_terraform(content, filepath, repo_full, repo_url)

    def _extract_secrets(
        self,
        content: str,
        filepath: str,
        repo_full: str,
        repo_url: str
    ):
        """Run secret regexes against file content."""
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            # Skip commented lines
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "<!--", ";")):
                continue

            for pattern_name, regex, sensitivity in SECRET_REGEXES:
                match = regex.search(line)
                if not match:
                    continue

                # Get the matched value (group 2 if exists, else group 0)
                try:
                    value = match.group(2) if match.lastindex and match.lastindex >= 2 \
                            else match.group(0)
                except IndexError:
                    value = match.group(0)

                # Skip placeholders
                if _is_placeholder(value):
                    continue

                sens_level = {
                    "critical": SensitivityLevel.CRITICAL,
                    "high":     SensitivityLevel.HIGH,
                    "medium":   SensitivityLevel.MEDIUM,
                }.get(sensitivity, SensitivityLevel.HIGH)

                # Redact actual secret value in output
                redacted = value[:4] + "****" if len(value) > 4 else "****"

                content_str = (
                    f"Secret found [{pattern_name}] in "
                    f"{repo_full}/{filepath}:{line_num}  |  "
                    f"Value (redacted): {redacted}  |  "
                    f"Line: {stripped[:120]}"
                )

                self.signals.append(Signal(
                    target_org=self.target_org,
                    source_type=SourceType.GITHUB,
                    source_url=f"{repo_url}/blob/main/{filepath}#L{line_num}",
                    raw_content=content_str,
                    entities=[Entity(
                        name=pattern_name,
                        entity_type="SECRET_PATTERN",
                        confidence=0.9,
                        context=f"{pattern_name} found in {filepath}"
                    )],
                    sensitivity=sens_level,
                    sensitivity_reason=(
                        f"{pattern_name} pattern matched in "
                        f"{filepath} line {line_num}"
                    ),
                    metadata={
                        "pattern":   pattern_name,
                        "filepath":  filepath,
                        "line":      line_num,
                        "repo":      repo_full,
                        "redacted":  redacted,
                    }
                ))
                logger.warning(
                    f"     🔴 {pattern_name} in "
                    f"{filepath}:{line_num}"
                )

    def _extract_infrastructure(
        self,
        content: str,
        filepath: str,
        repo_full: str,
        repo_url: str
    ):
        """Extract internal hostnames, IPs, and endpoints."""
        # Internal hostname pattern
        internal_pattern = re.compile(
            r'(?i)[\w\-]+\.(internal|corp|local|intranet|private)'
            r'[\w\.\-]*'
        )
        # Cloud endpoints
        cloud_pattern = re.compile(
            r'[\w\-]+\.(s3\.amazonaws\.com|'
            r'blob\.core\.windows\.net|'
            r'storage\.googleapis\.com|'
            r'eks\.amazonaws\.com|'
            r'rds\.amazonaws\.com)'
        )

        found_infra = set()

        for pattern, entity_type, reason in [
            (internal_pattern, "INTERNAL_HOSTNAME",
             "Internal hostname found in source code"),
            (cloud_pattern, "CLOUD_ENDPOINT",
             "Cloud service endpoint found in source code"),
        ]:
            for match in pattern.finditer(content):
                hostname = match.group(0).strip("\"',;")
                if hostname not in found_infra and len(hostname) > 5:
                    found_infra.add(hostname)
                    self.signals.append(Signal(
                        target_org=self.target_org,
                        source_type=SourceType.GITHUB,
                        source_url=f"{repo_url}/blob/main/{filepath}",
                        raw_content=(
                            f"Infrastructure reference in "
                            f"{repo_full}/{filepath}: {hostname}"
                        ),
                        entities=[Entity(
                            name=hostname,
                            entity_type=entity_type,
                            confidence=0.9,
                            context=f"Found in {filepath}"
                        )],
                        sensitivity=SensitivityLevel.HIGH,
                        sensitivity_reason=reason,
                        metadata={
                            "hostname": hostname,
                            "filepath": filepath,
                            "repo":     repo_full,
                        }
                    ))

    def _extract_tech_stack(
        self,
        content: str,
        filepath: str,
        repo_full: str,
        repo_url: str
    ):
        """Extract technology mentions from file contents."""
        content_lower = content.lower()
        found_techs   = set()

        for keyword, entity_type in TECH_KEYWORDS.items():
            if keyword in content_lower and entity_type not in found_techs:
                found_techs.add(entity_type)

        if found_techs:
            entities = [
                Entity(
                    name=t, entity_type=t,
                    confidence=0.85,
                    context=f"Technology detected in {filepath}"
                )
                for t in found_techs
            ]
            self.signals.append(Signal(
                target_org=self.target_org,
                source_type=SourceType.GITHUB,
                source_url=f"{repo_url}/blob/main/{filepath}",
                raw_content=(
                    f"Technology stack in {repo_full}/{filepath}: "
                    f"{', '.join(found_techs)}"
                ),
                entities=entities,
                sensitivity=SensitivityLevel.LOW,
                sensitivity_reason="Technology stack fingerprinted from source",
                metadata={
                    "technologies": list(found_techs),
                    "filepath":     filepath,
                    "repo":         repo_full,
                }
            ))

    # ── Specialised file parsers ──────────────────────────────────────────

    def _parse_dockerfile(
        self, content: str, filepath: str,
        repo_full: str, repo_url: str
    ):
        """Extract intelligence from Dockerfile contents."""
        entities  = []
        findings  = []

        for line in content.split("\n"):
            line = line.strip()

            # FROM → base image reveals OS and runtime
            if line.upper().startswith("FROM "):
                image = line[5:].split()[0]
                findings.append(f"Base image: {image}")
                entities.append(Entity(
                    name=image,
                    entity_type="DOCKER_IMAGE",
                    confidence=1.0,
                    context=f"Base image in {filepath}"
                ))

            # ENV → environment variables (potential secrets)
            elif line.upper().startswith("ENV "):
                env_line = line[4:].strip()
                findings.append(f"ENV: {env_line[:80]}")
                # Check if ENV contains a real value
                if "=" in env_line:
                    key, _, val = env_line.partition("=")
                    if not _is_placeholder(val.strip()):
                        entities.append(Entity(
                            name=key.strip(),
                            entity_type="ENV_VARIABLE",
                            confidence=0.8,
                            context=f"ENV variable in Dockerfile: {key}"
                        ))

            # EXPOSE → internal service ports
            elif line.upper().startswith("EXPOSE "):
                port = line[7:].strip()
                findings.append(f"Exposed port: {port}")
                entities.append(Entity(
                    name=f"port:{port}",
                    entity_type="SERVICE_PORT",
                    confidence=1.0,
                    context=f"Internal service port in {filepath}"
                ))

        if findings:
            self.signals.append(Signal(
                target_org=self.target_org,
                source_type=SourceType.GITHUB,
                source_url=f"{repo_url}/blob/main/{filepath}",
                raw_content=(
                    f"Dockerfile analysis — {repo_full}/{filepath}: "
                    f"{' | '.join(findings[:8])}"
                ),
                entities=entities,
                sensitivity=SensitivityLevel.HIGH,
                sensitivity_reason=(
                    "Dockerfile reveals container configuration, "
                    "base images, and service ports"
                ),
                metadata={
                    "filepath": filepath,
                    "repo":     repo_full,
                    "findings": findings,
                }
            ))

    def _parse_docker_compose(
        self, content: str, filepath: str,
        repo_full: str, repo_url: str
    ):
        """Extract service names, images, and env vars from docker-compose."""
        service_pattern = re.compile(r'^\s{2}(\w[\w\-]+):\s*$', re.MULTILINE)
        image_pattern   = re.compile(r'image:\s*(.+)')
        port_pattern    = re.compile(r'[-\s]+"?(\d+):(\d+)"?')

        services = service_pattern.findall(content)
        images   = image_pattern.findall(content)
        ports    = port_pattern.findall(content)

        entities = []
        findings = []

        for svc in services:
            findings.append(f"service:{svc}")
            entities.append(Entity(
                name=svc,
                entity_type="DOCKER_SERVICE",
                confidence=0.95,
                context=f"Docker service in {filepath}"
            ))

        for img in images[:10]:
            img = img.strip().strip("'\"")
            findings.append(f"image:{img}")
            entities.append(Entity(
                name=img,
                entity_type="DOCKER_IMAGE",
                confidence=0.95,
                context=f"Docker image in {filepath}"
            ))

        for host_port, container_port in ports[:10]:
            findings.append(f"port:{host_port}→{container_port}")

        if findings:
            self.signals.append(Signal(
                target_org=self.target_org,
                source_type=SourceType.GITHUB,
                source_url=f"{repo_url}/blob/main/{filepath}",
                raw_content=(
                    f"docker-compose analysis — {repo_full}/{filepath}: "
                    f"{' | '.join(findings[:10])}"
                ),
                entities=entities,
                sensitivity=SensitivityLevel.HIGH,
                sensitivity_reason=(
                    "docker-compose reveals service architecture, "
                    "images, and port mappings"
                ),
                metadata={
                    "services": services,
                    "images":   images,
                    "filepath": filepath,
                    "repo":     repo_full,
                }
            ))

    def _parse_terraform(
        self, content: str, filepath: str,
        repo_full: str, repo_url: str
    ):
        """Extract cloud provider and resource hints from Terraform files."""
        provider_pattern  = re.compile(r'provider\s+"(\w+)"')
        resource_pattern  = re.compile(r'resource\s+"([\w_]+)"\s+"([\w_]+)"')
        region_pattern    = re.compile(
            r'region\s*=\s*"(us-east-[12]|us-west-[12]|'
            r'eu-west-[123]|ap-southeast-[12]|[a-z]+-[a-z]+-\d)"'
        )

        providers = provider_pattern.findall(content)
        resources = resource_pattern.findall(content)
        regions   = region_pattern.findall(content)

        entities = []
        findings = []

        for p in set(providers):
            findings.append(f"provider:{p}")
            entities.append(Entity(
                name=p.upper(),
                entity_type="CLOUD_PROVIDER",
                confidence=1.0,
                context=f"Terraform provider in {filepath}"
            ))

        for r_type, r_name in resources[:10]:
            findings.append(f"resource:{r_type}.{r_name}")

        for region in set(regions):
            findings.append(f"region:{region}")
            entities.append(Entity(
                name=region,
                entity_type="CLOUD_REGION",
                confidence=1.0,
                context=f"Cloud region in Terraform config"
            ))

        if findings:
            self.signals.append(Signal(
                target_org=self.target_org,
                source_type=SourceType.GITHUB,
                source_url=f"{repo_url}/blob/main/{filepath}",
                raw_content=(
                    f"Terraform analysis — {repo_full}/{filepath}: "
                    f"{' | '.join(findings[:10])}"
                ),
                entities=entities,
                sensitivity=SensitivityLevel.HIGH,
                sensitivity_reason=(
                    "Terraform config reveals cloud provider, "
                    "regions, and infrastructure resources"
                ),
                metadata={
                    "providers": providers,
                    "regions":   regions,
                    "filepath":  filepath,
                    "repo":      repo_full,
                }
            ))

    # ── Contributors ──────────────────────────────────────────────────────

    async def _collect_contributors(
        self, client, repo_full: str, repo_url: str
    ):
        contributors = await self._get(
            client,
            f"{self.base_url}/repos/{repo_full}/contributors",
            {"per_page": 10}
        )
        if not contributors or not isinstance(contributors, list):
            return

        for c in contributors[:5]:
            username      = c.get("login", "")
            contributions = c.get("contributions", 0)
            if not username:
                continue

            self.signals.append(Signal(
                target_org=self.target_org,
                source_type=SourceType.GITHUB,
                source_url=c.get("html_url", ""),
                raw_content=(
                    f"Contributor: {username} — "
                    f"{contributions} commits to {repo_full}"
                ),
                entities=[Entity(
                    name=username,
                    entity_type="GITHUB_USER",
                    confidence=1.0,
                    context=f"{contributions} commits to {repo_full}"
                )],
                sensitivity=SensitivityLevel.MEDIUM,
                sensitivity_reason=(
                    "Developer identity linked to organization codebase"
                ),
                metadata={
                    "username":      username,
                    "contributions": contributions,
                    "repo":          repo_full,
                }
            ))

    # ── Commit scanning ───────────────────────────────────────────────────

    async def _scan_commits(
        self, client, repo_full: str, repo_url: str
    ):
        commits = await self._get(
            client,
            f"{self.base_url}/repos/{repo_full}/commits",
            {"per_page": 30}
        )
        if not commits or not isinstance(commits, list):
            return

        sensitive_keywords = [
            "secret", "password", "token", "key", "credential",
            "fix leak", "remove secret", "delete key", "oops",
            "accidentally", "revert secret", "hotfix prod",
            "remove password", "remove token", "remove api",
        ]

        for commit in commits:
            data    = commit.get("commit", {})
            message = data.get("message", "").lower()
            author  = data.get("author", {})
            name    = author.get("name", "")
            email   = author.get("email", "")
            sha     = commit.get("sha", "")[:8]

            if not any(k in message for k in sensitive_keywords):
                continue

            entities = []
            if email and "@" in email and not _is_placeholder(email):
                entities.append(Entity(
                    name=email,
                    entity_type="EMAIL_ADDRESS",
                    confidence=0.95,
                    context=f"Commit author in {repo_full}"
                ))
            if name:
                entities.append(Entity(
                    name=name,
                    entity_type="PERSON",
                    confidence=0.95,
                    context=f"Commit author in {repo_full}"
                ))

            self.signals.append(Signal(
                target_org=self.target_org,
                source_type=SourceType.GITHUB,
                source_url=f"{repo_url}/commit/{commit.get('sha','')}",
                raw_content=(
                    f"Sensitive commit [{sha}] by {name}: "
                    f"{data.get('message','')[:200]}"
                ),
                entities=entities,
                sensitivity=SensitivityLevel.HIGH,
                sensitivity_reason=(
                    f"Commit message suggests sensitive data "
                    f"was added or removed: {message[:80]}"
                ),
                metadata={
                    "sha":   sha,
                    "name":  name,
                    "email": email,
                    "message": data.get("message", ""),
                    "repo":  repo_full,
                }
            ))
            logger.info(f"     ⚠️  Sensitive commit [{sha}]: {message[:60]}")

    # ── Repo metadata signal ──────────────────────────────────────────────

    def _add_repo_metadata_signal(self, repo: Dict):
        full        = repo.get("full_name", "")
        description = repo.get("description", "") or ""
        language    = repo.get("language", "") or ""
        topics      = repo.get("topics", [])
        url         = repo.get("html_url", "")

        combined = f"{description} {language} {' '.join(topics)}".lower()
        entities = [
            Entity(
                name=full,
                entity_type="GITHUB_REPOSITORY",
                confidence=1.0,
                context=f"Public repository: {description}"
            )
        ]
        if language:
            entities.append(Entity(
                name=language,
                entity_type="PROGRAMMING_LANGUAGE",
                confidence=1.0,
                context=f"Primary language of {full}"
            ))
        for kw, etype in TECH_KEYWORDS.items():
            if kw in combined:
                entities.append(Entity(
                    name=kw, entity_type=etype,
                    confidence=0.8,
                    context=f"Technology in repo metadata"
                ))

        self.signals.append(Signal(
            target_org=self.target_org,
            source_type=SourceType.GITHUB,
            source_url=url,
            raw_content=(
                f"Repository: {full} | Language: {language} | "
                f"Description: {description} | "
                f"Topics: {', '.join(topics)}"
            ),
            entities=entities,
            sensitivity=SensitivityLevel.LOW,
            sensitivity_reason="Public repository metadata",
            metadata={
                "repo":        full,
                "language":    language,
                "description": description,
                "topics":      topics,
                "stars":       repo.get("stargazers_count", 0),
            }
        ))

    # ── HTTP helper ───────────────────────────────────────────────────────

    async def _get(
        self, client, url: str, params: dict
    ) -> Optional[any]:
        """
        Single HTTP GET with rate limit awareness.
        Returns parsed JSON or None on failure.
        """
        try:
            self._api_calls += 1
            response = await client.get(url, params=params)

            # Check rate limit headers
            remaining = int(
                response.headers.get("X-RateLimit-Remaining", 100)
            )
            if remaining < 10:
                logger.warning(
                    f"  GitHub rate limit low ({remaining}) — "
                    f"pausing 30s"
                )
                await asyncio.sleep(30)

            if response.status_code == 200:
                return response.json()
            if response.status_code == 403:
                logger.warning("  GitHub rate limit hit — pausing 60s")
                await asyncio.sleep(60)
            return None

        except Exception as e:
            logger.debug(f"  GET failed {url}: {e}")
            return None