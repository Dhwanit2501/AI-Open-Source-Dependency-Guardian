import json
import re
import os

def parse_dependency_file(file_name, file_content):
    """
    Detects file type and calls the appropriate parser.
    Returns a dictionary with dependencies and devDependencies (if any).
    """
    ext = os.path.splitext(file_name)[1]

    if ext == ".json":
        return parse_package_json(file_content), "json"

    elif ext == ".txt":
        return {"dependencies": parse_requirements(file_content), "devDependencies": {}}, "txt"

    else:
        raise ValueError("Unsupported file type. Upload package.json or requirements.txt")

def get_prefix(version):
    if version is None:
        return ""
    match = re.match(r"^([\^~><=]+)", version)
    return match.group(1) if match else ""

def parse_package_json(file_content):
    """
    Parses package.json keeping dependencies, devDependencies,
    and peerDependencies separate. Supports scoped packages like @org/pkg.
    """
    data = json.loads(file_content)
    deps = {}
    dev_deps = {}
    peer_deps = {}

    for pkg, version in data.get("dependencies", {}).items():
        deps[pkg] = {
            "prefix": get_prefix(version),
            "version": normalize_version(version)
        }

    for pkg, version in data.get("devDependencies", {}).items():
        dev_deps[pkg] = {
            "prefix": get_prefix(version),
            "version": normalize_version(version)
        }

    for pkg, version in data.get("peerDependencies", {}).items():
        peer_deps[pkg] = {
            "prefix": get_prefix(version),
            "version": normalize_version(version)
        }

    return {
        "dependencies": deps,
        "devDependencies": dev_deps,
        "peerDependencies": peer_deps,
        "_raw": data
    }


def parse_requirements(file_content):
    """
    Parses requirements.txt supporting both pinned (pkg==version) 
    and unpinned (pkg) dependencies.
    """
    deps = {}
    for line in file_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        match = re.match(r"([a-zA-Z0-9_\-]+)==([\d\.]+)", line)
        if match:
            pkg, version = match.groups()
            deps[pkg] = {"prefix": "==", "version": version}
        else:
            deps[line] = {"prefix": "", "version": None}
    return deps


def normalize_version(version):
    """
    Removes symbols like ^, ~, >=, <= for version comparison.
    """
    if version is None:
        return None
    return re.sub(r"^[\^~><=]+", "", version)