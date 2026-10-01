"""Refresh the README screenshots in docs/images from the demo dashboard.

    pip install playwright pillow
    python -m playwright install chromium
    python -m lodestar demo
    python scripts/readme_screenshots.py
"""
import asyncio
from pathlib import Path

from PIL import Image
from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "images"
URL = (ROOT / "dist" / "lodestar-dashboard.html").as_uri()
ABS = "s=>{const r=document.querySelector(s).getBoundingClientRect();return {x:r.left+scrollX,y:r.top+scrollY,width:r.width,height:r.height}}"


async def open_page(browser, w=1440, h=900, scheme="dark"):
    pg = await browser.new_page(viewport={"width": w, "height": h}, color_scheme=scheme)
    await pg.goto(URL)
    await pg.wait_for_timeout(1200)
    return pg


async def section(pg, sel, name, maxh):
    bb = await pg.evaluate(ABS, sel)
    await pg.screenshot(path=str(OUT / name), full_page=True,
                        clip={"x": max(0, bb["x"] - 24), "y": bb["y"] - 16, "width": min(1440, bb["width"] + 48),
                              "height": min(maxh, bb["height"] + 32)})


async def main():
    OUT.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as p:
        b = await p.chromium.launch()
        pg = await open_page(b)
        await pg.screenshot(path=str(OUT / "dashboard-overview.png"), full_page=True, clip={"x": 0, "y": 0, "width": 1440, "height": 1180})
        await pg.add_style_tag(content=".top{position:static!important}")
        await section(pg, "#desk-sec", "decision-desk.png", 1120)
        await pg.click(".item>button")
        await section(pg, ".focus", "focus-queue.png", 1000)
        await section(pg, "#ext-sec", "external-intel.png", 1000)
        await pg.click(".sug >> text=decisions")
        await section(pg, "#chat-fraud", "chat-and-fraud.png", 900)
        b1, b2 = await pg.evaluate(ABS, "#kri"), await pg.evaluate(ABS, "#controls")
        await pg.screenshot(path=str(OUT / "kris-controls.png"), full_page=True,
                            clip={"x": 16, "y": b1["y"] - 70, "width": 1408, "height": min(1300, b2["y"] + b2["height"] - b1["y"] + 70)})
        pg2 = await open_page(b)
        labels = await pg2.eval_on_selector_all("#org option", "els=>els.map(e=>e.textContent)")
        await pg2.select_option("#org", label=next(x for x in labels if "Helionyx" in x))
        await pg2.add_style_tag(content=".top{position:static!important}")
        await section(pg2, "#ext-sec", "external-intel-utility.png", 900)
        m = await open_page(b, 400, 900)
        await m.screenshot(path=str(OUT / "mobile.png"), full_page=True, clip={"x": 0, "y": 0, "width": 400, "height": 1500})
        light = await open_page(b)
        await light.click("#theme")
        await light.screenshot(path=str(OUT / "overview-light.png"), clip={"x": 0, "y": 0, "width": 1440, "height": 900})
        await b.close()
    for f in OUT.glob("*.png"):   # keep the repository small
        Image.open(f).convert("RGB").quantize(colors=256, dither=Image.Dither.NONE).save(f, optimize=True)
    print("Screenshots written to", OUT)


if __name__ == "__main__":
    asyncio.run(main())
