#!/usr/bin/env python3
"""Builds the sources of the documentation site (GitHub Pages) into site-src/.

The Markdown in README.md and docs/ is the single source; it is written to
read well on GitHub. For the site this script:
  - makes README.md the home page (index.md), with a hero and feature
    cards in place of its GitHub-only header,
  - turns links to files outside docs/ (examples/, LICENSE, ...) into links
    to those files on GitHub,
  - adds the blank line Python-Markdown needs before a list that directly
    follows a paragraph line (GitHub doesn't need it),
  - drops the "← Documentation · Previous · Next" line at the top of each
    page (the site has its own navigation),
  - publishes the release notes of versions that have a git tag.

    python scripts/build_site.py && mkdocs build --strict
"""
import os
import re
import shutil
import subprocess

REPO = "https://github.com/OprekLabs/grepalert"
ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUT = os.path.join(ROOT, "site-src")
LINK = re.compile(r"\]\(([^)\s]+)\)")
SRC = re.compile(r'(src|href)="([^"]+)"')


def rewrite(text, src_dir, out_dir):
    """Rewrites the relative links of a page that lives in src_dir (relative
    to the repository) and is published in out_dir (relative to the site)."""

    def fix(m):
        target = m.group(1)
        if "://" in target or target.startswith(("#", "mailto:")):
            return m.group(0)
        path, _, anchor = target.partition("#")
        anchor = "#" + anchor if anchor else ""
        repo_path = os.path.normpath(os.path.join(src_dir, path)).replace("\\", "/")
        if repo_path == "README.md":
            site_path = "index.md"
        elif repo_path == "docs/releases":
            site_path = "releases/index.md"
        elif repo_path.startswith("docs/"):
            site_path = repo_path[len("docs/"):]
        else:
            kind = "tree" if os.path.isdir(os.path.join(ROOT, repo_path)) else "blob"
            return f"]({REPO}/{kind}/main/{repo_path}{anchor})"
        rel = os.path.relpath(site_path, out_dir or ".").replace("\\", "/")
        return f"]({rel}{anchor})"

    def fix_html(m):
        # Raw HTML (e.g. the README's logo): same rules as Markdown links.
        new = fix(re.match(r"\]\((.+)\)", "](" + m.group(2) + ")"))
        return f'{m.group(1)}="{new[2:-1]}"'

    return SRC.sub(fix_html, LINK.sub(fix, text))


HOME_TOP = """---
hide: [navigation]
---

<div class="ga-hero" markdown>
<img src="docs/assets/logo.svg" class="ga-hero__logo" alt="">
<h1>grepalert</h1>
<p class="ga-hero__tagline">Alerts from your logs in five minutes.<br>No Loki, no Elasticsearch, no database.</p>
<p class="ga-hero__lead">{lead}</p>

[Get started](docs/install.md){{ .md-button .md-button--primary }}
[Rule cookbook](docs/cookbook.md){{ .md-button }}
[GitHub](https://github.com/OprekLabs/grepalert){{ .md-button }}
</div>

<div class="grid cards" markdown>

-   :material-file-search-outline:{{ .lg .middle }} **Files or Kubernetes pods**

    ---

    Follows log files through rotation, or the pods a label selector picks. Positions are saved, so nothing is lost or sent twice.

-   :material-message-text-outline:{{ .lg .middle }} **Your message, not the raw line**

    ---

    Pull values out of the line and write the alert yourself: *"Critical, DS1 is suspended"*, for Slack, Teams, Opsgenie or any webhook.

-   :material-bell-sleep-outline:{{ .lg .middle }} **No alert storms**

    ---

    Suppression windows with one summary afterwards, and the same alert from many servers combined into one.

-   :material-source-branch-check:{{ .lg .middle }} **Safe rule changes**

    ---

    Versions and rollback, a dry run on real logs, and staged rollout that stops by itself when a change misbehaves.

-   :material-feather:{{ .lg .middle }} **Small by design**

    ---

    Two single-file programs, no database, no queue. An agent stays around 20 MB of memory, even at 100 MB/s of logs.

-   :material-shield-account-outline:{{ .lg .middle }} **Ready for a team**

    ---

    Rules from GitHub or GitLab, sign-in with SSO, roles and an audit log in the dashboard.

</div>
"""


def home(readme):
    """The README with its GitHub-only header (centred logo and title, the
    link to this site) replaced by the site's hero and feature cards."""
    lines = readme.split("\n")
    end = next(i for i, l in enumerate(lines) if l.startswith("📖"))
    lead = next(l for l in lines[:end] if l and not l.startswith("<"))
    return HOME_TOP.format(lead=lead) + "\n".join(lines[end + 1:])


LIST_ITEM = re.compile(r"^(?:[-*+]|\d+\.) ")


def separate_lists(text):
    """Makes GitHub-style lists read the same in Python-Markdown:
      - content nested in a list item is indented to 4 spaces per level
        (GitHub also accepts 2 or 3, Python-Markdown doesn't), and
      - a list right after a paragraph line ("**Revoking:**" then "- …")
        gets the blank line Python-Markdown needs before it.
    Code blocks are moved with their list item but not changed inside."""
    out = []
    stack = []         # per open list item: (source content column, site content column)
    fence, shift = None, 0
    for line in text.split("\n"):
        body = line.lstrip()
        indent = len(line) - len(body)
        if fence:
            if body.startswith(fence):
                fence = None
            out.append(" " * max(0, indent + shift) + body if line.strip() else line)
            continue
        if not body:
            out.append(line)
            continue
        while stack and indent < stack[-1][0]:
            stack.pop()
        new = stack[-1][1] + indent - stack[-1][0] if stack else indent
        if body.startswith(("```", "~~~")):
            fence, shift = body[:3], new - indent
        elif LIST_ITEM.match(body):
            prev = out[-1].lstrip() if out else ""
            if prev and not LIST_ITEM.match(prev) and not prev.startswith(("|", "#", ">", "<")):
                out.append("")
            new = stack[-1][1] if stack else indent
            stack.append((indent + LIST_ITEM.match(body).end(), new + 4))
        out.append(" " * new + body)
    return "\n".join(out)


def drop_nav_line(text):
    lines = text.split("\n")
    if lines and lines[0].startswith("[← Documentation"):
        lines = lines[1:]
        while lines and not lines[0].strip():
            lines = lines[1:]
    return "\n".join(lines)


def write(rel, text):
    path = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def tags():
    try:
        out = subprocess.run(["git", "tag", "-l", "v*"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return set()
    return set(out.split())


def version_key(name):
    return [int(p) if p.isdigit() else p for p in re.split(r"[.\-]", name.lstrip("v").removesuffix(".md"))]


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    shutil.copytree(os.path.join(ROOT, "docs", "assets"), os.path.join(OUT, "assets"),
                    ignore=shutil.ignore_patterns("*.py", "__pycache__"))

    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
        write("index.md", rewrite(separate_lists(home(f.read())), ".", ""))

    for name in sorted(os.listdir(os.path.join(ROOT, "docs"))):
        if not name.endswith(".md"):
            continue
        with open(os.path.join(ROOT, "docs", name), encoding="utf-8") as f:
            write(name, rewrite(separate_lists(drop_nav_line(f.read())), "docs", ""))

    # Release notes: only versions that were tagged (the next one is a draft).
    released = tags()
    notes = [n for n in os.listdir(os.path.join(ROOT, "docs", "releases"))
             if n.endswith(".md") and n[:-3] in released]
    notes.sort(key=version_key, reverse=True)
    index = ["# Release notes", "",
             f"What each version brings. Downloads are on [GitHub Releases]({REPO}/releases).", ""]
    for n in notes:
        tag = n[:-3]
        with open(os.path.join(ROOT, "docs", "releases", n), encoding="utf-8") as f:
            body = f.read()
        write(f"releases/{n}", f"# grepalert {tag}\n\n" + rewrite(separate_lists(body), "docs/releases", "releases"))
        first = re.sub(r"\s+", " ", body.strip().split("\n\n")[0])
        index += [f"## [{tag}]({n})", "", first, ""]
    if not notes:
        index.append("No releases yet.")
    write("releases/index.md", "\n".join(index) + "\n")
    print(f"site sources in {OUT}: {len(os.listdir(OUT))} entries, release notes for {', '.join(n[:-3] for n in notes) or 'none'}")


if __name__ == "__main__":
    main()
