#!/usr/bin/env python3
"""Assemble the published GitHub Pages tree.

The repository keeps the original site on main:/docs and the current v3 site
on v3:/docs. GitHub Pages can publish only one source branch/path, so this
script builds the publication tree used by gh-pages:

  /      <- main:/docs
  /v3/   <- v3:/docs
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
from pathlib import Path


V3_TOP_LEVEL_EXCLUDES = {
    ".nojekyll",
    "CNAME",
    "robots.txt",
    "sitemap.xml",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root-docs", required=True, help="main branch docs directory")
    parser.add_argument("--v3-docs", required=True, help="v3 branch docs directory")
    parser.add_argument("--output", required=True, help="output publication directory")
    parser.add_argument("--root-ref", default="", help="main commit/ref used for root docs")
    parser.add_argument("--v3-ref", default="", help="v3 commit/ref used for /v3 docs")
    return parser.parse_args()


def assert_safe_output(output: Path, sources: list[Path]) -> None:
    resolved_output = output.resolve()
    if resolved_output == Path("/"):
        raise SystemExit("refusing to use / as output")
    for source in sources:
        resolved_source = source.resolve()
        if resolved_output == resolved_source:
            raise SystemExit(f"output must not equal source directory: {source}")
        if resolved_source in resolved_output.parents:
            continue
        if resolved_output in resolved_source.parents:
            raise SystemExit(f"output must not contain source directory: {source}")


def copy_tree(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise SystemExit(f"missing source directory: {source}")
    shutil.copytree(source, destination, dirs_exist_ok=True)


def remove_v3_publication_only_files(v3_output: Path) -> None:
    for name in V3_TOP_LEVEL_EXCLUDES:
        path = v3_output / name
        if path.is_file() or path.is_symlink():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)


def adjust_v3_index_metadata(v3_output: Path) -> None:
    index = v3_output / "index.html"
    if not index.is_file():
        return

    text = index.read_text(encoding="utf-8")
    text = text.replace(
        '<meta property="og:url" content="https://blastwall.org/">',
        '<meta property="og:url" content="https://blastwall.org/v3/">',
    )
    index.write_text(text, encoding="utf-8")


def write_manifest(output: Path, root_ref: str, v3_ref: str) -> None:
    manifest = {
        "generated_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "root": {
            "source": "main:/docs",
            "ref": root_ref,
        },
        "v3": {
            "source": "v3:/docs",
            "ref": v3_ref,
            "path": "/v3/",
        },
    }
    (output / "v3" / "published-from.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    args = parse_args()
    root_docs = Path(args.root_docs)
    v3_docs = Path(args.v3_docs)
    output = Path(args.output)

    assert_safe_output(output, [root_docs, v3_docs])
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    copy_tree(root_docs, output)

    v3_output = output / "v3"
    copy_tree(v3_docs, v3_output)
    remove_v3_publication_only_files(v3_output)
    adjust_v3_index_metadata(v3_output)
    write_manifest(output, args.root_ref, args.v3_ref)

    print(f"Published tree assembled at {output}")
    print(f"  /    from main:/docs {args.root_ref}".rstrip())
    print(f"  /v3 from v3:/docs {args.v3_ref}".rstrip())


if __name__ == "__main__":
    main()
