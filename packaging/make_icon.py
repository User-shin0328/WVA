"""Render WVA's own simple vector mark to Windows icon sizes."""
from pathlib import Path
from PIL import Image, ImageDraw

image = Image.new("RGBA", (256, 256), (13, 17, 19, 255))
draw = ImageDraw.Draw(image)
draw.line([(35,66),(82,190),(128,105),(174,190),(221,66)], fill=(88,201,188,255), width=9, joint="curve")
draw.line([(35,220),(221,220)], fill=(88,201,188,255), width=5)
image.save(Path(__file__).with_name("WVA.ico"), sizes=[(16,16),(32,32),(48,48),(64,64),(128,128),(256,256)])
