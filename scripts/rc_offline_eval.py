#!/usr/bin/env python3
"""Offline RC grid regression evaluator. No network/browser/verifier calls."""
import argparse,json,time,sys
from collections import defaultdict
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import cv2
from engines.rc.yolo_onnx import get_yolo

ap=argparse.ArgumentParser()
ap.add_argument('--manifest',required=True)
ap.add_argument('--dump-dir',default='/tmp/rc_challenge_dumps')
ap.add_argument('--out',default='/tmp/rc_offline_eval.json')
a=ap.parse_args()
M=json.load(open(a.manifest)); Y=get_yolo(); assert Y.ensure()
rows=[]; agg=defaultdict(lambda:{'tp':0,'fp':0,'fn':0,'exact':0,'n':0,'ms':[]})
for s in M['samples']:
 p=Path(a.dump_dir)/s['file']; gt=set(s['gt']); t=time.perf_counter()
 if not p.exists():
  rows.append({**s,'error':'missing'}); continue
 im=cv2.imread(str(p)); pred=set(Y.tiles_combined(im,s['target'],int(s['n'])) or [])
 ms=(time.perf_counter()-t)*1000; tp=len(gt&pred);fp=len(pred-gt);fn=len(gt-pred);exact=pred==gt
 r={**s,'pred':sorted(pred),'tp':tp,'fp':fp,'fn':fn,'exact':exact,'ms':round(ms,1)};rows.append(r)
 z=agg[s['target']];z['tp']+=tp;z['fp']+=fp;z['fn']+=fn;z['exact']+=int(exact);z['n']+=1;z['ms'].append(ms)
summary={}
for k,z in agg.items():
 pr=z['tp']/(z['tp']+z['fp']) if z['tp']+z['fp'] else 0
 rc=z['tp']/(z['tp']+z['fn']) if z['tp']+z['fn'] else 0
 summary[k]={'samples':z['n'],'exact_rate':z['exact']/z['n'],'precision':pr,'recall':rc,'avg_ms':sum(z['ms'])/len(z['ms'])}
TP=sum(z['tp'] for z in agg.values());FP=sum(z['fp'] for z in agg.values());FN=sum(z['fn'] for z in agg.values());N=sum(z['n'] for z in agg.values());EX=sum(z['exact'] for z in agg.values())
out={'version':M['version'],'rows':rows,'per_target':summary,'overall':{'samples':N,'exact_rate':EX/N if N else 0,'precision':TP/(TP+FP) if TP+FP else 0,'recall':TP/(TP+FN) if TP+FN else 0}}
Path(a.out).write_text(json.dumps(out,indent=2));print(json.dumps(out,indent=2))
