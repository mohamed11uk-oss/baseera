set -e
O=${1:-/workspace/rec/out}; DST=${2:-$O/demo.mp4}
ffmpeg -y -v error -i $O/s1.mp4 -i $O/app.mp4 -i $O/end.mp4 -i /workspace/baseera/docs/voiceover_tight.wav -filter_complex \
"[0:v]fade=t=in:st=0:d=0.6,fade=t=out:st=30.1:d=0.4,setsar=1[a];[1:v]fade=t=in:st=0:d=0.4,fade=t=out:st=92.15:d=0.35,setsar=1[b];[2:v]fade=t=in:st=0:d=0.35,fade=t=out:st=10.84:d=0.8,setsar=1[c];[a][b][c]concat=n=3:v=1:a=0,scale=in_range=pc:out_range=tv,format=yuv420p[v];[3:a]afade=t=out:st=133.9:d=0.7[au]" \
-map "[v]" -map "[au]" -c:v libx264 -preset slow -crf 18 -profile:v high -r 30 -c:a aac -b:a 192k -ar 48000 -ac 2 -color_range tv -colorspace bt709 -color_primaries bt709 -color_trc bt709 -movflags +faststart -t 134.64 $DST
ffprobe -v error -show_entries format=duration:stream=codec_name,width,height,duration,r_frame_rate -of compact $DST
