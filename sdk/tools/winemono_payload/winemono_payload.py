#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Ahmed ARIF <arif.ing@outlook.com>
#
# Builds the Wine Mono payload of a OpenNT release:
#   opennt-wine-mono-<version>-<release>-<arch>.msi  the upstream Wine Mono MSI with the
#   assemblies rebuilt from patches/ (build_assemblies.sh, docker) and the runtime DLLs rebuilt
#   from patches/mono-runtime-*.patch (build_runtime.sh, docker) swapped into image.cab, and
#   the Windows Runtime projection built from winrt/ added next to mscorlib, and the mscorlib type
#   library exported by tlbgen/ installed and registered like the .NET Framework one.
# The MSI is rewritten with gcab and msibuild (msitools).

import argparse
import hashlib
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

VERSION = "11.3.0"
UPSTREAM = {
    "x86": "df2dfc1665c2511882e7cabd56eafd0c0a3d94e5a7e86f969277f6c189d418d3",
    "arm64": "b0c47d374efaf22cbff76cb10488ac2d1627b067e085aef7acec573884120e0f",
}
ASSEMBLIES = {
    "mscorlib": "lib\\mono\\4.5\\mscorlib.dll",
    "System": "lib\\mono\\gac\\System\\4.0.0.0__b77a5c561934e089\\System.dll",
    "System.Security": "lib\\mono\\gac\\System.Security\\4.0.0.0__b03f5f7f11d50a3a\\System.Security.dll",
    "System.ServiceProcess": "lib\\mono\\gac\\System.ServiceProcess\\4.0.0.0__b03f5f7f11d50a3a\\System.ServiceProcess.dll",
    "WindowsBase": "lib\\mono\\gac\\WindowsBase\\4.0.0.0__31bf3856ad364e35\\WindowsBase.dll",
}
RUNTIMES = {
    "x86": "bin\\libmono-2.0-x86.dll",
    "x86_64": "bin\\libmono-2.0-x86_64.dll",
    "arm64": "bin\\libmono-2.0-arm64.dll",
}
ADDITIONS = {
    "Windows.built.dll": ("lib\\mono\\4.5\\Windows.dll", "lib|mono|4.5", "Windows.dll"),
}
TYPELIBS = {
    32: ("Framework\\v4.0.30319\\mscorlib.tlb", "mscorlib-tlb", "mscorlib.tlb"),
    64: ("Framework64\\v4.0.30319\\mscorlib.tlb", "mscorlib-tlb64", "mscorlib.tlb"),
}
MSCORLIB_TYPELIB = "TypeLib\\{BED7F4EA-1A96-11D2-8F08-00A0C9A6186D}\\2.4"
TABLE_ROWS = {
    "Directory": [
        ["NETFX", "WindowsFolder", "netfx|Microsoft.NET"],
        ["NETFX|Framework", "NETFX", "FRAMEW~1|Framework"],
        ["NETFX|Framework|v4.0.30319", "NETFX|Framework", "V40303~1|v4.0.30319"],
        ["NETFX|Framework64", "NETFX", "FRAMEW~2|Framework64"],
        ["NETFX|Framework64|v4.0.30319", "NETFX|Framework64", "V40303~1|v4.0.30319"],
    ],
    "Component": [
        ["mscorlib-tlb", "{24C30574-2647-50BB-BD6C-DCF531ECA25E}", "NETFX|Framework|v4.0.30319", "0", "", TYPELIBS[32][0]],
        ["mscorlib-tlb64", "{77435B6F-1AD8-5EA6-B08F-C0781C1E4199}", "NETFX|Framework64|v4.0.30319", "0", "VersionNT64", TYPELIBS[64][0]],
    ],
    "FeatureComponents": [
        ["wine_mono", "mscorlib-tlb"],
        ["wine_mono", "mscorlib-tlb64"],
    ],
    "InstallExecuteSequence": [
        ["RemoveRegistryValues", "", "650"],
        ["WriteRegistryValues", "", "900"],
    ],
    "Registry": [
        ["mscorlib.tlb.version", "0", MSCORLIB_TYPELIB, "", "mscorlib.dll", "mscorlib-tlb"],
        ["mscorlib.tlb.flags", "0", MSCORLIB_TYPELIB + "\\FLAGS", "", "0", "mscorlib-tlb"],
        ["mscorlib.tlb.win32", "0", MSCORLIB_TYPELIB + "\\0\\win32", "", "[#" + TYPELIBS[32][0] + "]", "mscorlib-tlb"],
        ["mscorlib.tlb.win64", "0", MSCORLIB_TYPELIB + "\\0\\win64", "", "[#" + TYPELIBS[64][0] + "]", "mscorlib-tlb64"],
    ],
}
NEW_TABLES = {
    "Registry": ["Registry\tRoot\tKey\tName\tValue\tComponent_", "s72\ti2\tl255\tL255\tL0\ts72", "Registry\tRegistry"],
}


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fetch(arch, directory):
    path = directory / f"wine-mono-{VERSION}-{arch}.msi"
    if not path.exists() or sha256(path) != UPSTREAM[arch]:
        url = f"https://dl.winehq.org/wine/wine-mono/{VERSION}/wine-mono-{VERSION}-{arch}.msi"
        with urllib.request.urlopen(url) as response, open(path, "wb") as out:
            shutil.copyfileobj(response, out)
    if sha256(path) != UPSTREAM[arch]:
        sys.exit(f"{path}: unexpected sha256")
    return path


def export_table(msi, name, path):
    with open(path, "wb") as out:
        run("msiinfo", "export", msi, name, stdout=out)
    raw = path.read_bytes().decode("utf-8")
    eol = "\r\n" if "\r\n" in raw else "\n"
    return eol, raw.split(eol)


def file_hashes(msi, work):
    _, rows = export_table(msi, "MsiFileHash", work / "hash.idt")
    keys = set(ASSEMBLIES.values())
    return {r.split("\t")[0]: r.split("\t")[2:6] for r in rows[3:] if r.split("\t")[0] in keys}


def repack(src, dst, replacements, additions):
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        cab = work / "image.cab"
        with open(cab, "wb") as out:
            run("msiinfo", "extract", src, "image.cab", stdout=out)
        order = run("gcab", "-t", cab, capture_output=True, text=True).stdout.splitlines()
        replacements = {key: path for key, path in replacements.items()
                        if key in order or key not in RUNTIMES.values()}
        missing = [key for key in replacements if key not in order]
        if missing:
            sys.exit(f"{src}: not in image.cab: {', '.join(missing)}")
        tree = work / "x"
        tree.mkdir()
        run("gcab", "-x", "-C", tree, cab)
        existing = [key for key in additions if key in order]
        if existing:
            sys.exit(f"{src}: already in image.cab: {', '.join(existing)}")
        for key, path in replacements.items():
            shutil.copyfile(path, tree.joinpath(*key.split("\\")))
        for key, (_, _, path) in additions.items():
            tree.joinpath(*key.split("\\")).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, tree.joinpath(*key.split("\\")))
        order += list(additions)
        newcab = work / "new.cab"
        run("gcab", "-c", "-z", newcab, *[key.replace("\\", "/") for key in order], cwd=tree)
        if run("gcab", "-t", newcab, capture_output=True, text=True).stdout.splitlines() != order:
            sys.exit(f"{src}: cabinet order changed")
        info = {}
        for key, path in list(replacements.items()) + [(key, value[2]) for key, value in additions.items()]:
            data = Path(path).read_bytes()
            info[key] = (len(data), struct.unpack("<4i", hashlib.md5(data).digest()))
        eol, media = export_table(src, "Media", work / "Media.idt")
        media_rows = [row.split("\t") for row in media[3:] if row]
        if len(media_rows) != 1 or not media_rows[0][3].startswith("#"):
            sys.exit(f"{src}: expected one embedded cabinet")
        sequence = int(media_rows[0][1])
        media_rows[0][1] = str(sequence + len(additions))
        (work / "Media.idt").write_bytes(eol.join(media[:3] + ["\t".join(media_rows[0]), ""]).encode("utf-8"))
        tables = [work / "Media.idt"]
        for name in ("File", "MsiFileHash"):
            path = work / f"{name}.idt"
            eol, rows = export_table(src, name, path)
            seen = set()
            for index, row in enumerate(rows[3:], 3):
                cols = row.split("\t")
                if cols[0] not in info:
                    continue
                size, parts = info[cols[0]]
                if name == "File":
                    cols[3] = str(size)
                else:
                    cols[2:6] = [str(value) for value in parts]
                rows[index] = "\t".join(cols)
                seen.add(cols[0])
            if seen != set(replacements):
                sys.exit(f"{src}: {name} rows missing for {', '.join(sorted(set(replacements) - seen))}")
            while rows and rows[-1] == "":
                rows.pop()
            for index, (key, (component, filename, _)) in enumerate(additions.items(), 1):
                size, parts = info[key]
                if name == "File":
                    rows.append("\t".join([key, component, filename, str(size), "", "", "", str(sequence + index)]))
                else:
                    rows.append("\t".join([key, "0"] + [str(value) for value in parts]))
            path.write_bytes((eol.join(rows) + eol).encode("utf-8"))
            tables.append(path)
        shutil.copyfile(src, dst)
        for name, rows in TABLE_ROWS.items():
            path = work / f"{name}.idt"
            if name in NEW_TABLES:
                eol, table = "\r\n", NEW_TABLES[name] + [""]
            else:
                eol, table = export_table(src, name, path)
            while table and table[-1] == "":
                table.pop()
            existing = {row.split("\t")[0] for row in table[3:]}
            clash = [row[0] for row in rows if row[0] in existing and name not in ("FeatureComponents",)]
            if clash:
                sys.exit(f"{src}: {name} already has {', '.join(clash)}")
            path.write_bytes((eol.join(table + ["\t".join(row) for row in rows]) + eol).encode("utf-8"))
            tables.append(path)
        run("msibuild", dst, *[arg for table in tables for arg in ("-i", table)], "-a", "image.cab", newcab)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path, help="work directory (sources, docker build, upstream MSIs)")
    parser.add_argument("out", type=Path, help="output directory")
    parser.add_argument("--release", default="1", help="OpenNT release number of the payload")
    parser.add_argument("--widl", default=shutil.which("widl"), help="widl of a OpenNT build (host-tools/bin/widl)")
    args = parser.parse_args()
    for tool in ("msiinfo", "msibuild", "gcab", "docker", "git", "7zz"):
        if not shutil.which(tool):
            sys.exit(f"{tool} is required")
    if not args.widl:
        sys.exit("widl is required (--widl)")
    args.work.mkdir(parents=True, exist_ok=True)
    args.out.mkdir(parents=True, exist_ok=True)
    upstream = args.work / "upstream"
    upstream.mkdir(exist_ok=True)
    msis = {arch: fetch(arch, upstream) for arch in UPSTREAM}
    with tempfile.TemporaryDirectory() as tmp:
        hashes = {arch: file_hashes(msi, Path(tmp)) for arch, msi in msis.items()}
    if hashes["x86"] != hashes["arm64"] or len(hashes["x86"]) != len(ASSEMBLIES):
        sys.exit("the x86 and arm64 MSIs do not ship the same assemblies")
    build = args.work / "build"
    run("bash", Path(__file__).with_name("build_assemblies.sh"), build, msis["x86"])
    runtime = args.work / "runtime"
    run("bash", Path(__file__).with_name("build_runtime.sh"), runtime)
    replacements = {key: build / f"{name}.patched.dll" for name, key in ASSEMBLIES.items()}
    replacements.update({key: runtime / f"libmono-2.0-{arch}.patched.dll" for arch, key in RUNTIMES.items()})
    additions = {key: (component, filename, build / built) for built, (key, component, filename) in ADDITIONS.items()}
    root = Path(__file__).resolve().parents[3]
    includes = [f"-I{root / 'sdk' / 'include' / 'psdk'}", f"-I{root / 'sdk' / 'include' / 'reactos'}"]
    typelib = args.work / "typelib"
    for bits, (key, component, filename) in TYPELIBS.items():
        out = typelib / f"win{bits}"
        out.mkdir(parents=True, exist_ok=True)
        run(args.widl, f"--win{bits}", "-t", "-o", out / "stdole2.tlb", *includes, root / "dll" / "win32" / "stdole2.tlb" / "std_ole_v2.idl")
        run(args.widl, f"--win{bits}", "-t", "-o", out / "mscorlib.tlb", *includes, f"-L{out}", build / f"mscorlib{bits}.idl")
        additions[key] = (component, filename, out / "mscorlib.tlb")
    for arch, msi in msis.items():
        dst = args.out / f"opennt-wine-mono-{VERSION}-{args.release}-{arch}.msi"
        repack(msi, dst, replacements, additions)
        print(f"{dst.name} {dst.stat().st_size} {sha256(dst)}")


if __name__ == "__main__":
    main()
