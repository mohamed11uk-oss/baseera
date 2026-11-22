import base64, os, time, subprocess
class Recorder:
    """CDP screencast -> jpeg frames with timestamps -> CFR mp4."""
    def __init__(self, page, outdir):
        self.page=page; self.outdir=outdir; os.makedirs(outdir,exist_ok=True)
        self.frames=[]; self.n=0
    async def start(self):
        self.cdp=await self.page.context.new_cdp_session(self.page)
        self.cdp.on("Page.screencastFrame", self._on)
        self.t0=time.time()
        await self.cdp.send("Page.startScreencast",{"format":"jpeg","quality":95,"maxWidth":1920,"maxHeight":1080,"everyNthFrame":1})
    def _on(self, ev):
        import asyncio
        fn=os.path.join(self.outdir,f"f{self.n:06d}.jpg"); self.n+=1
        open(fn,"wb").write(base64.b64decode(ev["data"]))
        self.frames.append((ev["metadata"]["timestamp"],fn))
        asyncio.ensure_future(self.cdp.send("Page.screencastFrameAck",{"sessionId":ev["sessionId"]}))
    async def mark(self):
        return time.time()
    async def stop(self):
        self.t1=time.time()
        await self.cdp.send("Page.stopScreencast")
    def render(self, out, start_wall=None, duration=None, fps=30):
        """start_wall: wall-clock time that maps to t=0 of output; duration: exact output length (hold last frame)."""
        fr=sorted(self.frames)
        s=start_wall if start_wall else fr[0][0]
        end=s+duration if duration else self.t1
        lst=os.path.join(self.outdir,"list.txt")
        lines=[]
        # frames before start: use latest frame <= s as first
        first=[f for f in fr if f[0]<=s]
        seq=([ (s,first[-1][1]) ] if first else [(s,fr[0][1])]) + [f for f in fr if s<f[0]<end]
        for i,(t,fn) in enumerate(seq):
            nt=seq[i+1][0] if i+1<len(seq) else end
            lines.append(f"file '{fn}'\nduration {max(nt-t,0.001):.4f}")
        lines.append(f"file '{seq[-1][1]}'")
        open(lst,"w").write("\n".join(lines)+"\n")
        subprocess.run(["ffmpeg","-y","-v","error","-f","concat","-safe","0","-i",lst,
            "-vf",f"scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:color=0x0b2e3a,fps={fps},format=yuv420p",
            "-t",f"{end-s:.3f}","-c:v","libx264","-crf","16","-preset","medium",out],check=True)
