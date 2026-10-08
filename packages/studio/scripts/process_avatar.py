"""Turn the source velociraptor PNG into a transparent-bg, pure-black-raptor
icon so it renders cleanly in both themes.

Input heuristic: any near-white pixel (all channels > WHITE_THRESHOLD) becomes
fully transparent; everything else becomes opaque pure-black. The dark-mode
CSS ``filter: invert(1)`` rule then flips pure-black → white while the
transparent background shows through the nav in both themes.

Run:
    PYTHONPATH=. .venv/bin/python scripts/process_avatar.py
"""
from pathlib import Path

from PIL import Image

SRC = Path.home() / "Downloads" / "velociraptor_avatar.png"
DST = Path(__file__).resolve().parent.parent / "studio" / "static" / "velociraptor.png"
WHITE_THRESHOLD = 235  # any channel above this is treated as background


def main() -> None:
    if not SRC.is_file():
        raise SystemExit(f"source image missing: {SRC}")

    src = Image.open(SRC).convert("RGBA")
    pixels = src.load()
    w, h = src.size
    bg, fg = 0, 0
    for y in range(h):
        for x in range(w):
            r, g, b, _a = pixels[x, y]
            if r > WHITE_THRESHOLD and g > WHITE_THRESHOLD and b > WHITE_THRESHOLD:
                pixels[x, y] = (0, 0, 0, 0)  # transparent
                bg += 1
            else:
                pixels[x, y] = (0, 0, 0, 255)  # solid black (invert-safe)
                fg += 1
    DST.parent.mkdir(parents=True, exist_ok=True)
    src.save(DST, "PNG", optimize=True)
    print(f"wrote {DST}")
    print(f"  background pixels (transparent): {bg}")
    print(f"  foreground pixels (pure black):  {fg}")
    print(f"  dimensions: {w}x{h}")


if __name__ == "__main__":
    main()
