#!/usr/bin/env python3
"""Aggregate verified benchmark samples and update only dependent paper data/prose.
Run from any directory. No third-party Python packages required.
"""
from pathlib import Path
import argparse,csv,json,hashlib,statistics,collections,re,math

a=argparse.ArgumentParser();a.add_argument('--run',type=Path,required=True);a.add_argument('--paper',type=Path,required=True);a.add_argument('--apply',action='store_true');args=a.parse_args()
run=args.run.resolve();paper=args.paper.resolve();root=Path(__file__).resolve().parents[1]
sources=root/'results/paper-data-sources.json'
if args.apply and sources.exists() and json.loads(sources.read_text()).get('figure_run_overrides'):
 raise SystemExit('Newer partial figure data are registered. Use update_figures67.py to preserve them; do not reapply the older full run.')
meta=json.loads((run/'metadata.json').read_text());assert meta['complete'] is True
for name,digest in meta['source_sha256'].items():
 assert hashlib.sha256((root/name).read_bytes()).hexdigest()==digest, f'Benchmark source changed: {name}'
groups=collections.defaultdict(list);raw=list(csv.DictReader((run/'samples.csv').open()))
for row in raw:
 key=(row['family'],row['operation'],int(row['q']),int(row['public']),int(row['users']))
 ns=int(row['duration_ns']);assert ns>=0;groups[key].append(ns/1e6)
expected=meta['protocol_rounds']
for key,values in groups.items():
 count=meta['primitive_rounds'] if key[0]=='primitives' else expected*(meta['threshold'] if key[0]=='lifecycle' and key[1]=='blind_sign' else 1)
 assert len(values)==count,(key,len(values),count)
assert len(raw)==5*meta['primitive_rounds']+expected*(7*7+6*2+5*6)
summary=[]
for key,v in sorted(groups.items()):
 summary.append(dict(zip(['family','operation','q','public','users'],key),samples=len(v),mean_ms=statistics.mean(v),median_ms=statistics.median(v),stddev_ms=statistics.stdev(v),min_ms=min(v),max_ms=max(v)))
with (run/'summary.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=list(summary[0]));w.writeheader();w.writerows(summary)
def mean(f,op,q=0,p=0,u=0):return statistics.mean(groups[(f,op,q,p,u)])
e1,e2,et,pair,hg=[mean('primitives',op) for op in ['E_G1','E_G2','E_GT','pairing','H_G']]
t=3;k=1
# These formulae reproduce the existing table, not fresh peer implementations.
def estimate(s,op,q):
 if s=='Ours':return {'issuer':(8*q+7)*e1+hg,'user':(8*q+2*t+4)*e1+hg,'generate':11*e1+(2*q+4)*e2,'verify':7*e1+(q+3)*e2+2*pair}[op]
 if s=='Coconut':return {'issuer':(8*q+5)*e1,'user':(8*q+2*t+4)*e1,'generate':2*e1+(2*q+2)*e2,'verify':2*e1+(q+3)*e2+2*pair}[op]
 if s=='DkvSSO':return {'issuer':13*q*e1,'user':14*q*e1,'generate':(22+3*k)*q*e1,'verify':4*q*e1}[op]
 if s=='Jia2025':return {'generate':10*e1+(q+7)*e2+pair,'verify':10*e1+(q+6)*e2+2*et+3*pair}[op]
 raise ValueError(s)
models=[]
for q in [1,3,5,7]:
 for op,schemes in [('issuer',['DkvSSO','Coconut','Ours']),('user',['DkvSSO','Coconut','Ours']),('generate',['DkvSSO','Jia2025','Coconut','Ours']),('verify',['DkvSSO','Jia2025','Coconut','Ours'])]:
  for scheme in schemes:models.append({'family':'comparison','scheme':scheme,'operation':op,'q':q,'users':0,'estimate_ms':estimate(scheme,op,q)})
for users in [20,40,60,80,100]:
 for scheme,v in [('Shi2023',users/2*(e2+pair+t*et)),('FADID-TT',users/2*((t+1)*et))]:models.append({'family':'tracing','scheme':scheme,'operation':'trace','q':0,'users':users,'estimate_ms':v})
with (run/'operation_estimates.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=list(models[0]));w.writeheader();w.writerows(models)
(run/'data_manifest.json').write_text(json.dumps({'selected_run':run.name,'updater_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'statistic':'arithmetic mean; all recorded samples retained; no outlier removal','sample_count':len(raw),'samples_sha256':hashlib.sha256((run/'samples.csv').read_bytes()).hexdigest(),'measured':['DAC lifecycle','selective disclosure','verified threshold tracing plus registry lookup','group operations and hash-to-group'],'estimated':['four cross-scheme computational comparison panels','Shi2023/FADID-TT tracing curves'],'retained':['original RDKG and on-chain gas coordinates'],'comparison_scope':'Existing Table II counts; k=1, t=3. Core Ours issuance excludes receipt-side V_part, reported separately; peer counting scopes have not been re-audited.','fixture_attributes':'Synthetic field values 41..(40+q); identity is SHA-256 of a fixed synthetic registration string reduced modulo group order. Secret keys and operation randomness are fresh.'},indent=2)+'\n')
with (run/'issuance_verification_estimates.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=['q','t','core_user_ms','receipt_verification_ms','complete_user_estimate_ms']);w.writeheader()
 for q in [1,3,5,7]:
  core=estimate('Ours','user',q);verification=t*(q+1)*e2+2*t*pair
  w.writerow({'q':q,'t':t,'core_user_ms':core,'receipt_verification_ms':verification,'complete_user_estimate_ms':core+verification})
s=paper.read_text();original=s
def current_data_match(text):
 expected={
  'fig:cred_issuance_cost':[[(q,mean('lifecycle',op,q)) for q in range(1,8)] for op in ['prepare','blind_sign','obtain','generate','verify']],
  'fig:token_selective_disclosure':[[(p,mean('selective',op,7,p)) for p in range(1,7)] for op in ['generate','verify']],
  'fig:comp_overhead_t3':[[(i,mean('tracing','total',1,0,u)) for i,u in enumerate(range(20,101,20),1)],[(i,u/2*(e2+pair+t*et)) for i,u in enumerate(range(20,101,20),1)],[(i,u/2*(t+1)*et) for i,u in enumerate(range(20,101,20),1)]]}
 for label,op,schemes in [('fig:Cred_issue_i_comp','issuer',['DkvSSO','Coconut','Ours']),('fig:Cred_issue_u_comp','user',['DkvSSO','Coconut','Ours']),('fig:Token_generate_comp','generate',['DkvSSO','Jia2025','Coconut','Ours']),('fig:Token_verify_comp','verify',['DkvSSO','Jia2025','Coconut','Ours'])]:expected[label]=[[(q,estimate(scheme,op,q)) for q in [1,3,5,7]] for scheme in schemes]
 for label,series in expected.items():
  pos=text.index('\\label{'+label+'}');lo=text.rfind('\\begin{axis}',0,pos);hi=text.index('\\end{axis}',lo)
  plots=re.findall(r'\\addplot(?:\+?\[[^\]]*\])?\s+coordinates\s*\{(.*?)\};',text[lo:hi],re.S)
  if len(plots)!=len(series):
   print("Series-count mismatch",label,len(plots),len(series));return False
  for plot,want in zip(plots,series):
   pts=[(int(x),float(y)) for x,y in re.findall(r'\((\d+),([0-9.]+)\)',plot)]
   if len(pts)!=len(want) or any(x!=a or abs(y-b)>0.00000051 for (x,y),(a,b) in zip(pts,want)):
    print("Data mismatch",label,pts,want);return False
 return True
stamp=run/'paper-data-update.json'
if stamp.exists():
 previous=json.loads(stamp.read_text())
 if previous.get('applied') and current_data_match(s):
  previous['last_verified_paper_sha256']=hashlib.sha256(s.encode()).hexdigest()
  previous['data_validation']='All plotted series match this run to six-decimal TeX precision; unrelated author edits preserved.'
  stamp.write_text(json.dumps(previous,indent=2)+'\n')
  print('Paper data match this run; summaries regenerated and unrelated author edits preserved.');raise SystemExit(0)
labels=['fig:cred_issuance_cost','fig:token_selective_disclosure','fig:comp_overhead_t3','fig:Cred_issue_i_comp','fig:Cred_issue_u_comp','fig:Token_generate_comp','fig:Token_verify_comp']
pattern=r'(\\addplot(?:\+?\[[^\]]*\])?\s+coordinates\s*\{)(.*?)(\};)'
def axis_span(text,label):
 pos=text.index('\\label{'+label+'}');start=text.rfind('\\begin{axis}',0,pos);end=text.index('\\end{axis}',start)+len('\\end{axis}');return start,end
legacy={}
for label in labels:
 lo,hi=axis_span(original,label);legacy[label]=[m.group(2).strip() for m in re.finditer(pattern,original[lo:hi],re.S)]
archive=run/'legacy-paper-coordinates.json'
if not archive.exists():archive.write_text(json.dumps({'paper_sha256':hashlib.sha256(original.encode()).hexdigest(),'coordinates':legacy},indent=2)+'\n')
changes=[]
def update_axis(label,series):
 global s
 lo,hi=axis_span(s,label);axis=s[lo:hi];matches=list(re.finditer(pattern,axis,re.S));assert len(matches)==len(series),(label,len(matches),len(series))
 idx=0
 def repl(m):
  nonlocal idx
  coords=' '.join(f'({x},{y:.6f})' for x,y in series[idx]);idx+=1;return m.group(1)+coords+m.group(3)
 axis=re.sub(pattern,repl,axis,flags=re.S)
 # Expand only an axis that would otherwise clip the new data.
 mx=max(y for row in series for _,y in row)
 ym=re.search(r'ymax\s*=\s*([0-9.]+)',axis)
 if ym and mx>float(ym.group(1)):
  axis=axis[:ym.start(1)]+str(math.ceil(mx*1.1/5)*5)+axis[ym.end(1):]
 if label=='fig:comp_overhead_t3':axis=axis.replace('ymin=0,','ymin=0.1,').replace('\\legend{Ours, \\cite{Shi2023AC},FADID-TT~\\cite{Liu2025DID}}','\\legend{Ours (measured), \\cite{Shi2023AC} (estimated), FADID-TT~\\cite{Liu2025DID} (estimated)}')
 if label=='fig:Cred_issue_u_comp':axis=re.sub(r'ymax\s*=\s*[0-9.]+','ymax='+str(max(13,math.ceil(mx*1.1/5)*5)),axis,count=1)
 s=s[:lo]+axis+s[hi:];changes.append(label)
update_axis(labels[0],[[(q,mean('lifecycle',op,q)) for q in range(1,8)] for op in ['prepare','blind_sign','obtain','generate','verify']])
update_axis(labels[1],[[(public,mean('selective',op,7,public)) for public in range(1,7)] for op in ['generate','verify']])
update_axis(labels[2],[[(i,mean('tracing','total',1,0,users)) for i,users in enumerate(range(20,101,20),1)],[(i,users/2*(e2+pair+t*et)) for i,users in enumerate(range(20,101,20),1)],[(i,users/2*(t+1)*et) for i,users in enumerate(range(20,101,20),1)]])
for label,op,schemes in [(labels[3],'issuer',['DkvSSO','Coconut','Ours']),(labels[4],'user',['DkvSSO','Coconut','Ours']),(labels[5],'generate',['DkvSSO','Jia2025','Coconut','Ours']),(labels[6],'verify',['DkvSSO','Jia2025','Coconut','Ours'])]:update_axis(label,[[(q,estimate(scheme,op,q)) for q in [1,3,5,7]] for scheme in schemes])
def replace(a,b):
 global s
 if a in s:s=s.replace(a,b)
 elif b not in s:raise AssertionError(a[:100])
s=s.replace('$T_{H_G}+V_{\\mathrm{part}}$','$T_{H_G}$',1)
s=s.replace('Comp. cost of credential issue on user (estimated)','Comp. cost of core credential issue on user (estimated)',1)
s=s.replace('$T_{H_G}$ denotes one hash-to-group evaluation, and $V_{\\mathrm{part}}=t(q+1)E_{G_2}+2t\\,t_p$ accounts for verifying $t$ partial signatures.','$T_{H_G}$ denotes one hash-to-group evaluation. The Cred-Issue user entry reports core issuance operations; receipt-side verification of $t$ partial credentials costs an additional $V_{\\mathrm{part}}=t(q+1)E_{G_2}+2t\\,t_p$, which is included in the measured $\\dacobtaincred$ timings but excluded from Figure~\\ref{fig:Cred_issue_u_comp}.',1)
replace('Baseline computational overhead of DAC algorithms vs. number of attributes','Measured computational overhead of revised DAC algorithms vs. number of attributes')
replace('Baseline computational cost vs. number of hidden attributes','Measured computational cost vs. number of disclosed attributes')
replace('Baseline threshold tracing cost vs. number of registered users','Tracing costs: measured Ours and operation-count estimates for related schemes')
for a,b in [('credential issue on issuer (baseline)','credential issue on issuer (estimated)'),('credential issue on user (baseline)','credential issue on user (estimated)'),('token generation (baseline)','token generation (estimated)'),('token verification (baseline)','token verification (estimated)')]:replace(a,b)
replace('(0.132 ms / 0.523 ms / 2.029 ms )',f'({e1:.6f} ms / {e2:.6f} ms / {et:.6f} ms)')
replace('(1.896 ms)',f'({pair:.6f} ms)')
# Existing hash-to-group symbol gets its measured calibration without changing any operation counts.
if '$T_{H_G}$: mean hash-to-group time' not in s:
 replace('$t_p$: time cost per pairing operation',f'$T_{{H_G}}$: mean hash-to-group time ({hg:.6f} ms), averaged over 500 runs; \\\\\n$t_p$: time cost per pairing operation')
old=r'''We implement our proposed scheme using Solidity for on-chain smart contract components, and Golang for the off-chain operations. The original DAC prototype uses the bn256 elliptic curve library. The measurements below are retained as baseline results: they do not include the revised commitment-consistency relation, signature mask, or verified tracing-share proofs, and do not validate the revised end-to-end protocol. These mechanisms must be implemented and benchmarked before drawing updated performance comparisons. 
Ethereum Sepolia test network is used to simulate the blockchain execution environment and measure on-chain gas overhead. The off-chain components are executed on a server equipped with a 3.8 GHz processor, 16 GB of memory, running Ubuntu 22.04. The proof-of-concept implementation is available on Github\footnote{\url{https://github.com/AppCrypto/RDKG-DAC}}.'''
new=r'''We use Solidity for the on-chain components and Go with the bn256 library for off-chain cryptographic operations. The revised DAC measurements use Go 1.25.4 on macOS (darwin/amd64 runtime), with one Go execution thread. Each protocol configuration is measured over 100 rounds after 10 warm-up rounds; primitive costs are averaged over 500 rounds. We report arithmetic means without discarding outliers. The local measurements include proof generation, input validation, proof verification, and verification of partial credentials; registration, policy review, network transport, and setup are excluded. Raw samples, dispersion statistics, and source hashes are retained in the accompanying experiments directory.
The original RDKG and on-chain measurements are retained from the reported Ubuntu 22.04 server setting (3.8 GHz processor, 16 GB memory), with Ethereum Sepolia for the on-chain evaluation. Cross-scheme comparison panels use the operation counts in Table~\ref{tab:computation-overhead} calibrated with the newly measured primitive costs; these are estimates rather than fresh implementations of the related schemes. The original prototype is available on Github\footnote{\url{https://github.com/AppCrypto/RDKG-DAC}}.'''
env_start=s.index('\\section{Experimental Results}')+len('\\section{Experimental Results}')
env_end=s.index('\\subsection{Performance of RDKG and Evolving DAO}',env_start)
old_env=s[env_start:env_end]
foot=re.search(r'\\footnote\{\\url\{[^}]+\}\}',old_env)
if foot:
 new=re.sub(r'\\footnote\{\\url\{[^}]+\}\}',lambda _:foot.group(0),new)
s=s[:env_start]+'\n'+new+'\n\n'+s[env_end:]
replace(r'''Except $\dacobtaincred$, which remains nearly constant, other operations show a linear growth with respect to $q$.''',r'''The measured costs generally increase with $q$. The cost of $\dacobtaincred$ now includes verifying $t$ partial credentials, in addition to unblinding and aggregation.''')
if 'By Table~' in s:
 a=s.index('By Table~\\ref{tab:computation-overhead}, we have compared');b=s.index('% In the previous subsection',a)
 s=s[:a]+r'''Table~\ref{tab:computation-overhead} and Figures~\ref{fig:Cred_issue_i_comp}--\ref{fig:Token_verify_comp} compare operation-count estimates using the same primitive calibration, with $(t,n)=(3,5)$ and $k=1$. The issuance estimates include the added commitment-consistency proof. Figure~\ref{fig:Cred_issue_u_comp} reports core user issuance operations, with receipt-side verification of partial credentials listed separately in Table~\ref{tab:computation-overhead}; the measured $\dacobtaincred$ costs in Figure~\ref{fig:cred_issuance_cost} include this verification. The counting scope of each row must be considered when comparing schemes. Figure~\ref{fig:Token_verify_comp} retains the lower estimated verification cost relative to~\cite{Jia2025AC}, due to fewer pairings and no $G_T$ exponentiations. Figure~\ref{fig:Token_generate_comp} shows that our generation cost is lower than~\cite{Jia2025AC} only for small attribute vectors under this calibration. These estimates are distinct from the measured protocol costs in Figures~\ref{fig:cred_issuance_cost} and~\ref{fig:token_selective_disclosure}.
 
 '''+s[b:]
 
replace(r'''Figure~\ref{fig:comp_overhead_t3} summarizes the threshold tracing cost with increasing the number of registered users, illustrating the baseline tracing cost before adding verified-share proofs.''',f'''Figure~\\ref{{fig:comp_overhead_t3}} reports our measured tracing cost, including partial-decryption proofs and an indexed registry lookup, and operation-count estimates for the related schemes, using $m/2$ expected comparisons for population scans. Across 20--100 registered synthetic users, our mean tracing time ranges from {min(mean('tracing','total',1,0,u) for u in range(20,101,20)):.3f} to {max(mean('tracing','total',1,0,u) for u in range(20,101,20)):.3f} ms. The cryptographic work does not scan the user population; variation in these local timings includes execution noise.''')
replace("The prototype results characterize baseline costs; end-to-end performance of the revised mechanisms remains to be measured.","The local measurements evaluate the revised off-chain mechanisms; network and deployment costs remain outside this evaluation.")
s=s.replace('the revised proofs and issuance mechanisms require further benchmarking.', 'we evaluate the revised off-chain issuance, presentation, and tracing mechanisms.')
# Intro contribution may still refer to the now completed measurements.
s=s.replace('characterizing the core costs and identifying the revised mechanisms that require further evaluation.', 'characterizing the revised off-chain costs in the evaluated settings.')
# Never change the cryptographic construction or analytic count rows.
for marker in ['\\section{Reconfigurable DKG and Evolving DAO}','\\section{Traceable DAC Based on Evolving DAO}']:
 assert marker in s
construction=lambda x:x[x.index('\\section{Reconfigurable DKG and Evolving DAO}'):x.index('\\renewcommand{\\arraystretch}',x.index('\\subsection{Security Analysis}'))]
assert construction(s)==construction(original),'Unexpected protocol/proof edit'
(run/'paper-data-update.json').write_text(json.dumps({'changed_figures':changes,'paper_before_sha256':hashlib.sha256(original.encode()).hexdigest(),'paper_after_sha256':hashlib.sha256(s.encode()).hexdigest(),'applied':args.apply},indent=2)+'\n')
if args.apply:paper.write_text(s)
print('Validated samples:',len(raw));print('Updated figure axes:',len(changes));print('Primitive means (ms):',e1,e2,et,pair,hg);print('Wrote summary.csv and operation_estimates.csv; paper applied:',args.apply)
