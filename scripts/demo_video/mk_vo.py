import subprocess,json
src="/workspace/baseera/docs/voiceover_final.wav"
secs=[(0.5,28.485),(29.985,58.145),(60.0,79.335),(110.0,125.72),(150.0,163.44)]
pre=[1.0,2.5,3.5,8.0,8.0]; tail=7.0
t=0;parts=[];timings=[]
for (a,b),g in zip(secs,pre):
    t+=g; timings.append((round(t,3),round(t+b-a,3))); t+=b-a
total=round(t+tail,3)
f=[]
for i,((a,b),g) in enumerate(zip(secs,pre)):
    f.append(f"[0:a]atrim={a}:{b},asetpts=PTS-STARTPTS[s{i}]")
    f.append(f"anullsrc=r=SR:cl=CL,atrim=0:{g}[g{i}]")
f.append(f"anullsrc=r=SR:cl=CL,atrim=0:{tail}[gt]")
f.append("".join(f"[g{i}][s{i}]" for i in range(5))+"[gt]concat=n=11:v=0:a=1[out]")
print(json.dumps({"sections":timings,"total":total}))
json.dump({"sections":timings,"total":total},open("/workspace/baseera/docs/voiceover_tight_timings.json","w"),indent=1)
open("/tmp/vo_filter.txt","w").write(";".join(f))
