"""
vendor.py - Download xterm.js (the maintained successor to the abandoned
term.js) and the fit addon, and unpack just the files we need into
static/vendor/. Run once: `python vendor.py`.

Uses the classic UMD builds (xterm 5.3.0 / xterm-addon-fit 0.8.0) so the
browser gets global `Terminal` and `FitAddon` with no bundler step.
"""

import io
import os
import sys
import tarfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(HERE, "static", "vendor")

PACKAGES = [
    # (tarball url, {member-in-tarball: output-filename})
    ("https://registry.npmjs.org/xterm/-/xterm-5.3.0.tgz", {
        "package/lib/xterm.js": "xterm.js",
        "package/css/xterm.css": "xterm.css",
    }),
    ("https://registry.npmjs.org/xterm-addon-fit/-/xterm-addon-fit-0.8.0.tgz", {
        "package/lib/xterm-addon-fit.js": "xterm-addon-fit.js",
    }),
]


def main():
    os.makedirs(VENDOR, exist_ok=True)
    for url, members in PACKAGES:
        print(f"-> {url}")
        with urllib.request.urlopen(url, timeout=60) as resp:
            blob = resp.read()
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            for member, out_name in members.items():
                try:
                    src = tar.extractfile(member)
                except KeyError:
                    src = None
                if src is None:
                    print(f"   !! missing {member}", file=sys.stderr)
                    sys.exit(1)
                out_path = os.path.join(VENDOR, out_name)
                with open(out_path, "wb") as fh:
                    fh.write(src.read())
                print(f"   wrote {out_name} ({os.path.getsize(out_path)} bytes)")
    print(f"Vendored into {VENDOR}")


if __name__ == "__main__":
    main()
