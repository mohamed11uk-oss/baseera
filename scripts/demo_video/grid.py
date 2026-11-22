import sys
from PIL import Image, ImageDraw
files=sys.argv[2:]; out=sys.argv[1]
ims=[Image.open(f) for f in files]; w,h=ims[0].size
cols=2; rows=(len(ims)+1)//2
g=Image.new("RGB",(w*cols,h*rows),"white"); d=ImageDraw.Draw(g)
for i,(f,im) in enumerate(zip(files,ims)):
    x,y=(i%cols)*w,(i//cols)*h; g.paste(im,(x,y)); d.rectangle([x,y,x+90,y+22],fill="black"); d.text((x+4,y+4),f.split('/')[-1],fill="yellow")
g.save(out)
