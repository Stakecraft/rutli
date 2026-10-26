#!/usr/bin/env python3
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
"""Write driver/THIRD-PARTY-LICENSES.txt for the jars bundled into rutli-driver.jar.

Usage: third-party-licenses-jvm.py <classpath-file> <output>

<classpath-file> holds `sbt export driver/Runtime/dependencyClasspath` (entries separated by ':'
or newlines). For each jar the license comes from its POM in the Coursier cache, or from OVERRIDES
when the POM inherits it from a parent. The license and notice files inside each jar are copied
verbatim; texts a jar does not carry come from driver/licenses/. A license outside ALLOWED fails
the run, so a new dependency under an unexpected license cannot slip into a release.
"""
import hashlib
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LICENSES_DIR = ROOT / "driver" / "licenses"

# SPDX id -> display name. Bouncy Castle's licence is MIT-style but has its own text.
ALLOWED = {
    "Apache-2.0": "Apache License 2.0",
    "MIT": "MIT License",
    "BSD-3-Clause": "BSD 3-Clause License",
    "MPL-2.0": "Mozilla Public License 2.0",
    "Bouncy-Castle": "Bouncy Castle Licence (MIT-style)",
}

# POM license names -> SPDX id.
NAME_PATTERNS = [
    (r"apache", "Apache-2.0"),
    (r"mozilla public license.*2\.0", "MPL-2.0"),
    (r"bouncy castle", "Bouncy-Castle"),
    (r"^mit\b|mit license", "MIT"),
    (r"bsd-3-clause|bsd 3-clause|new bsd", "BSD-3-Clause"),
]

# group:artifact -> SPDX id, for POMs that inherit the license from a parent, and the Canton API
# (published locally, no POM).
OVERRIDES = {
    "com.daml:kms-driver-api_2.13": "Apache-2.0",
    "org.slf4j:slf4j-api": "MIT",
    "com.google.protobuf:protobuf-java": "BSD-3-Clause",
    "com.google.guava:guava": "Apache-2.0",
    "com.google.guava:failureaccess": "Apache-2.0",
    "com.google.guava:listenablefuture": "Apache-2.0",
    "org.codehaus.mojo:animal-sniffer-annotations": "MIT",
}

# Texts that must ship but are not inside the jar (copyright lines for MIT/BSD).
EXTRA_TEXTS = {
    "com.google.protobuf:protobuf-java": "protobuf-java-LICENSE.txt",
    "org.codehaus.mojo:animal-sniffer-annotations": "animal-sniffer-annotations-LICENSE.txt",
}

# MPL-2.0 section 3.2: say where the source code is. pureconfig is used unmodified.
MPL_SOURCES = {
    "com.github.pureconfig": "https://github.com/pureconfig/pureconfig (tag v{version}), unmodified",
}

NOTICE_FILE = re.compile(r"(^|/)(LICEN[CS]E|NOTICE|COPYING)[^/]*$", re.IGNORECASE)


def coordinates(jar: Path):
    parts = jar.parts
    if "maven2" in parts:  # Coursier: .../maven2/<group path>/<artifact>/<version>/<file>.jar
        i = parts.index("maven2")
        group = ".".join(parts[i + 1 : -3])
        return group, parts[-3], parts[-2]
    if "local" in parts and parts[-2] == "jars":  # ivy local: .../local/<org>/<module>/<rev>/jars/<module>.jar
        return parts[-5], parts[-4], parts[-3]
    sys.exit(f"cannot read Maven coordinates from {jar}")


def pom_license(jar: Path, ga: str):
    if ga in OVERRIDES:
        return OVERRIDES[ga]
    pom = jar.with_suffix(".pom")
    if not pom.exists():
        sys.exit(f"{ga}: no POM next to {jar} and no override; add one to OVERRIDES")
    names = re.findall(r"<license>\s*<name>(.*?)</name>", pom.read_text(errors="replace"), re.S)
    for name in names:
        for pattern, spdx in NAME_PATTERNS:
            if re.search(pattern, name.strip(), re.IGNORECASE):
                return spdx
    sys.exit(f"{ga}: unrecognised license {names!r} in {pom}; add a pattern or an override")


def jar_notice_files(jar: Path):
    with zipfile.ZipFile(jar) as z:
        for name in sorted(z.namelist()):
            if NOTICE_FILE.search(name) and not name.endswith((".class", "/")):
                yield name, z.read(name).decode("utf-8", errors="replace").strip()


def main():
    cp_file, out = Path(sys.argv[1]), Path(sys.argv[2])
    entries = [e for e in re.split(r"[:\n]", cp_file.read_text()) if e.strip().endswith(".jar")]
    comps = []
    for e in entries:
        jar = Path(e.strip())
        group, artifact, version = coordinates(jar)
        ga = f"{group}:{artifact}"
        spdx = pom_license(jar, ga)
        if spdx not in ALLOWED:
            sys.exit(f"{ga}: license {spdx} is not allowed for bundling")
        comps.append((group, artifact, version, spdx, jar))
    comps.sort(key=lambda c: (c[0], c[1]))

    # Texts, deduplicated: identical texts from several jars are printed once.
    texts = {}  # sha -> (text, [labels])
    for group, artifact, version, _, jar in comps:
        ga = f"{group}:{artifact}"
        found = list(jar_notice_files(jar))
        if ga in EXTRA_TEXTS:
            found.append((f"(upstream) {EXTRA_TEXTS[ga]}", (LICENSES_DIR / EXTRA_TEXTS[ga]).read_text().strip()))
        for name, text in found:
            sha = hashlib.sha256(text.encode()).hexdigest()
            texts.setdefault(sha, (text, []))[1].append(f"{ga}:{version} {name}")

    w = []
    w.append("THIRD-PARTY SOFTWARE NOTICES AND LICENSES")
    w.append("Rütli KMS driver (rutli-driver.jar)")
    w.append("")
    w.append("rutli-driver.jar bundles the third-party components listed below. Rütli itself is")
    w.append("licensed under the Apache License, Version 2.0 (META-INF/rutli/LICENSE in this jar).")
    w.append("")
    w.append("This file is generated by scripts/third-party-licenses.sh. Do not edit by hand.")
    w.append("")
    w.append("Components")
    w.append("----------")
    for group, artifact, version, spdx, _ in comps:
        w.append(f"  {group}:{artifact}:{version}  [{spdx}]")
    mpl = [c for c in comps if c[3] == "MPL-2.0"]
    for group in sorted({c[0] for c in mpl}):
        version = next(c[2] for c in mpl if c[0] == group)
        src = next(v for k, v in MPL_SOURCES.items() if group.startswith(k))
        w.append("")
        w.append(f"  Source code of the {group} components (MPL-2.0): {src.format(version=version)}")

    used = sorted({c[3] for c in comps})
    for spdx in ("Apache-2.0", "MPL-2.0"):
        if spdx in used:
            text = (ROOT / "LICENSE").read_text() if spdx == "Apache-2.0" else (LICENSES_DIR / "MPL-2.0.txt").read_text()
            w += ["", "=" * 80, f"{ALLOWED[spdx]} ({spdx})",
                  "Applies to the components marked [" + spdx + "] above.", "-" * 80, text.strip()]

    w += ["", "=" * 80, "License and notice files of the components",
          "Reproduced verbatim from each component's jar, or from upstream where the jar has none.", "=" * 80]
    for text, labels in sorted(texts.values(), key=lambda t: t[1][0]):
        w += ["", "-" * 80] + [f"From {label}" for label in labels] + ["-" * 80, text]

    out.write_text("\n".join(w) + "\n")


if __name__ == "__main__":
    main()
