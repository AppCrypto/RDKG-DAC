#!/usr/bin/env python3
"""Update only Figure 6/7 coordinates from a validated partial benchmark run."""
from pathlib import Path
import argparse,collections,csv,hashlib,json,math,re,statistics
p=argparse.ArgumentParser();p.add_argument('--run',type=Path,required=True);p.add_argument('--paper',type=Path,required=True);p.add_argument('--apply',action='store_true');args=p.parse_args()
root=Path(__file__).resolve().parents[1];run=args.run.resolve();paper=args.paper.resolve();meta=json.loads((run/'metadata.json').read_text())
assert meta['complete'] and meta['suite']=='figures6-7'
for name,digest in meta['source_sha256'].items():assert hashlib.sha256((root/name).read_bytes()).hexdigest()==digest,f'Source changed: {name}'
groups=collections.defaultdict(list);raw=list(csv.DictReader((run/'samples.csv').open()))
for r in raw:groups[(r['family'],r['operation'],int(r['q']),int(r['public']))].append(int(r['duration_ns'])/1e6)
ops=['prepare','blind_sign','obtain','generate','verify']
expected={('lifecycle',op,q,0) for q in range(1,8) for op in ops}|{('selective',op,7,d) for d in range(1,7) for op in ['generate','verify']}
assert set(groups)==expected
assert len(raw)==meta['protocol_rounds']*(7*7+6*2)
summary=[]
for key,values in sorted(groups.items()):
 expected_n=meta['protocol_rounds']*(meta['threshold'] if key[0]=='lifecycle' and key[1]=='blind_sign' else 1)
 assert len(values)==expected_n and min(values)>=0
 summary.append(dict(zip(['family','operation','q','public'],key),samples=len(values),mean_ms=statistics.mean(values),median_ms=statistics.median(values),stddev_ms=statistics.stdev(values),min_ms=min(values),max_ms=max(values)))
with (run/'summary.csv').open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(summary[0]));w.writeheader();w.writerows(summary)
def mean(f,op,q,d):return statistics.mean(groups[(f,op,q,d)])
s=paper.read_text();before=s;previous={};updates={
'fig:cred_issuance_cost':[[(q,mean('lifecycle',op,q,0)) for q in range(1,8)] for op in ops],
'fig:token_selective_disclosure':[[(d,mean('selective',op,7,d)) for d in range(1,7)] for op in ['generate','verify']]}
pattern=r'(\\addplot\s+coordinates\s*\{)(.*?)(\};)'
def bounds(text,label):
 pos=text.index('\\label{'+label+'}');lo=text.rfind('\\begin{axis}',0,pos);hi=text.index('\\end{axis}',lo)+len('\\end{axis}');return lo,hi
for label,series in updates.items():
 lo,hi=bounds(s,label);axis=s[lo:hi];matches=list(re.finditer(pattern,axis,re.S));assert len(matches)==len(series)
 previous[label]=[m.group(2).strip() for m in matches];idx=0
 def repl(m):
  global idx
  points=' '.join(f'({x},{y:.6f})' for x,y in series[idx]);idx+=1;return m.group(1)+points+m.group(3)
 axis=re.sub(pattern,repl,axis,flags=re.S)
 ymax=re.search(r'ymax=([0-9.]+)',axis);mx=max(y for row in series for _,y in row)
 if ymax and mx>float(ymax.group(1)):axis=axis[:ymax.start(1)]+str(math.ceil(mx*1.1/5)*5)+axis[ymax.end(1):]
 s=s[:lo]+axis+s[hi:]
def exclude_axes(text):
 for label in updates:
  lo,hi=bounds(text,label);text=text[:lo]+'<updated-axis>'+text[hi:]
 return text
assert exclude_axes(s)==exclude_axes(before),'Unexpected edit outside Figure 6/7 axes'
archive=run/'previous-paper-coordinates.json'
if not archive.exists():archive.write_text(json.dumps({'paper_sha256':hashlib.sha256(before.encode()).hexdigest(),'coordinates':previous},indent=2)+'\n')
audit={'run':run.name,'sample_count':len(raw),'statistic':'arithmetic mean; no samples removed','samples_sha256':hashlib.sha256((run/'samples.csv').read_bytes()).hexdigest(),'updater_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'changed_figures':list(updates),'paper_before_sha256':hashlib.sha256(before.encode()).hexdigest(),'paper_after_sha256':hashlib.sha256(s.encode()).hexdigest(),'applied':args.apply,'all_other_paper_content_unchanged':True}
(run/'paper-update.json').write_text(json.dumps(audit,indent=2)+'\n')
if args.apply:
 paper.write_text(s)
 path=root/'results/paper-data-sources.json'
 sources=json.loads(path.read_text()) if path.exists() else {'default_run':'revised-20261028-serial','figure_run_overrides':{}}
 sources['figure_run_overrides'].update({label:run.name for label in updates});sources['note']='Only Figures 6/7 use the partial rerun; primitive calibration, tracing, RDKG/gas, Table II and Figures 9-12 retain their prior data.'
 path.write_text(json.dumps(sources,indent=2)+'\n')
print('Validated samples:',len(raw),'summary groups:',len(summary),'paper applied:',args.apply)
for q in [1,7]:print('q=',q,{op:round(mean('lifecycle',op,q,0),6) for op in ops})
