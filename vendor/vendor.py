#!/usr/bin/env python3
"""Copy commonware-consensus and commonware-cryptography out of a monorepo checkout.

Usage:
  vendor/vendor.py <checkout>         copy the crates, then apply commonware.patch
  vendor/vendor.py --diff <checkout>  rewrite commonware.patch from the copies

<checkout> is a commonwarexyz/monorepo checkout at the pinned rev.

Each manifest is rewritten so the crate builds outside the monorepo workspace: inherited
package fields, lints and dependencies are written out, and sibling commonware crates
become git dependencies at the checkout's rev. The sources are upstream's plus
commonware.patch, whose paths are upstream's so it also applies to a monorepo checkout.
"""

import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

GIT = "https://github.com/commonwarexyz/monorepo"
CRATES = {"consensus": "commonware-consensus", "cryptography": "commonware-cryptography"}
# Separate packages that live below the crate directories upstream.
SKIP = ["fuzz", "curve25519"]


def value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(v, list):
        return "[" + ", ".join(value(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{k} = {value(x)}" for k, x in v.items()) + " }"
    raise TypeError(v)


def spec(name, workspace_deps, rev):
    """The dependency `name` as the monorepo workspace declares it."""
    dep = workspace_deps[name]
    if isinstance(dep, str):
        dep = {"version": dep}
    dep = dict(dep)
    if "path" in dep:
        dep.pop("path")
        dep.pop("version", None)
        dep = {"git": GIT, "rev": rev, **dep}
    return dep


def merge(base, extra):
    out = dict(base)
    for k, v in extra.items():
        if k == "workspace":
            continue
        if k == "features":
            out[k] = sorted(set(out.get(k, [])) | set(v))
        else:
            out[k] = v
    return out


def rewrite(manifest, workspace, rev):
    package = workspace["package"]
    deps = workspace["dependencies"]
    lints = workspace["lints"]
    out = []
    section = ""
    for line in manifest.splitlines():
        header = re.fullmatch(r"\[(.+)\]", line.strip())
        if header:
            section = header.group(1)
        in_deps = section.endswith("dependencies")
        # A table for one dependency: `[target.'cfg(..)'.dependencies.name]`.
        table_dep = re.search(r"dependencies\.([A-Za-z0-9_-]+)$", section)
        if section == "package" and (m := re.fullmatch(r"([a-z-]+)\.workspace = true", line)):
            line = f"{m.group(1)} = {value(package[m.group(1)])}"
        elif section == "lints" and header:
            continue
        elif section == "lints" and line.strip() == "workspace = true":
            for tool, table in lints.items():
                out.append(f"[lints.{tool}]")
                out.extend(f"{k} = {value(v)}" for k, v in table.items())
                out.append("")
            out.pop()
            continue
        elif table_dep and line.strip() == "workspace = true":
            # The table sets its own features and default-features.
            name = table_dep.group(1)
            base = spec(name, deps, rev)
            base.pop("default-features", None)
            base.pop("features", None)
            out.extend(f"{k} = {value(v)}" for k, v in base.items())
            continue
        elif in_deps and (m := re.fullmatch(r"([A-Za-z0-9_-]+)\.workspace = true", line)):
            line = f"{m.group(1)} = {value(spec(m.group(1), deps, rev))}"
        elif in_deps and (m := re.fullmatch(r"([A-Za-z0-9_-]+) = (\{.*workspace = true.*\})", line)):
            extra = tomllib.loads(f"x = {m.group(2)}")["x"]
            line = f"{m.group(1)} = {value(merge(spec(m.group(1), deps, rev), extra))}"
        out.append(line)
    text = "\n".join(out) + "\n"
    assert "workspace" not in text, "unresolved workspace inheritance"
    return text


def diff(monorepo, vendor):
    """Write the difference between upstream and the copies, manifests aside."""
    patch = []
    for directory, name in CRATES.items():
        files = {p.relative_to(vendor / name) for p in (vendor / name).rglob("*") if p.is_file()}
        for file in sorted(files - {Path("Cargo.toml")}):
            upstream = f"{directory}/{file}"
            old = monorepo / upstream if (monorepo / upstream).exists() else "/dev/null"
            out = subprocess.run(
                ["diff", "-u", "--label", f"a/{upstream}", "--label", f"b/{upstream}", old, vendor / name / file],
                capture_output=True,
                text=True,
            )
            patch.append(out.stdout)
    (vendor / "commonware.patch").write_text("".join(patch))


def main():
    monorepo = Path(sys.argv[-1]).resolve()
    vendor = Path(__file__).resolve().parent
    if sys.argv[1] == "--diff":
        return diff(monorepo, vendor)
    rev = subprocess.check_output(["git", "-C", monorepo, "rev-parse", "HEAD"], text=True).strip()
    workspace = tomllib.loads((monorepo / "Cargo.toml").read_text())["workspace"]
    for directory, name in CRATES.items():
        target = vendor / name
        shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(monorepo / directory, target, ignore=shutil.ignore_patterns(*SKIP))
        manifest = (target / "Cargo.toml").read_text()
        (target / "Cargo.toml").write_text(rewrite(manifest, workspace, rev))
    # The workspace used to run the upstream tests: upstream lockfile, lints and profiles.
    root = (monorepo / "Cargo.toml").read_text()
    patches = "\n".join(f'{name} = {{ path = "{name}" }}' for name in CRATES.values())
    (vendor / "Cargo.toml").write_text(
        f"[workspace]\nmembers = {value(list(CRATES.values()))}\nresolver = \"2\"\n\n"
        f'[patch."{GIT}"]\n{patches}\n\n' + root[root.index("[profile.") :]
    )
    (vendor / ".config").mkdir(exist_ok=True)
    shutil.copy(monorepo / "nextest.toml", vendor / ".config" / "nextest.toml")
    for name in ["Cargo.lock", "clippy.toml"]:
        shutil.copy(monorepo / name, vendor / name)
    if (vendor / "commonware.patch").exists():
        patch = (vendor / "commonware.patch").read_text()
        for directory, name in CRATES.items():
            # One chunk per file, paths `a/<directory>/..`.
            chunks = re.findall(rf"^--- a/{directory}/.*?(?=^--- a/|\Z)", patch, re.M | re.S)
            subprocess.run(
                ["patch", "-p2", "-s", "-d", vendor / name], input="".join(chunks), text=True, check=True
            )
    print(f"vendored {', '.join(CRATES.values())} at {rev}")


if __name__ == "__main__":
    main()
