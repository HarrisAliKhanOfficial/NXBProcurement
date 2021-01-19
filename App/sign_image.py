from PIL import Image
from PIL import ImageFont
from PIL import ImageDraw
import datetime
import os

def add_signarture(url):
    filename, ext = os.path.splitext(url)
    
    img = Image.open(url)
    font_style = "impact.ttf"


    absolute_path = os.path.join(os.getcwd(), 'App', font_style)
    print(absolute_path)

    first_line = "Procurement Manager"
    second_line = "Digitally signed at"
    date_str = str(datetime.datetime.now())

    color = (0,0,0)
    font_size = 16

    margin_chars = "ZZZZ" # four characters away from the left border.
    size = (600,400)

    draw = img.thumbnail(size, Image.ANTIALIAS)
    draw = ImageDraw.Draw(img)

    font = ImageFont.truetype(absolute_path, font_size)
    max_len = font.getsize(date_str)[0] # width of the line
    single_char_width = font.getsize(margin_chars)[0]
    max_height = font.getsize(date_str)[1]

    x = img.size[0] - max_len - single_char_width
    y = img.size[1] - max_height*5

    draw.text((x, y), first_line, color,font=font)
    draw.text((x, y+20), second_line, color,font=font)
    draw.text((x, y+40), date_str, color,font=font)

    img.save(filename+ext)