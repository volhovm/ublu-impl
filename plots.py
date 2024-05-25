from glob import glob
import json
from collections import defaultdict
import numpy as np

a = defaultdict(dict)

for m in sorted(glob("target/criterion/*/*/new/estimates.json")):
    #print(m)
    with open(m) as fd:
        data = json.load(fd)

    #print(data["mean"]["point_estimate"], data["std_dev"]["point_estimate"])
    parts = m.split("/")
    #print(parts[2], int(parts[3]))
    a[parts[2]][int(parts[3])] = (data["mean"]["point_estimate"], data["std_dev"]["point_estimate"])
    #break

#print(a)

colors = {"Escrow": "red",
          "KeyGen": "blue",
          "Setup": "green",
          "Update": "yellow",
          "VfEscrow": "magenta",
          "VfHint": "dashed",
          #"VfHistory": "dotted",
          "VfKeyGen": "black",
          #"Decrypt": "black"
          }

xs = [x for x in sorted(a["VfHistory"].keys())]
xsm = [x-1 for x in sorted(a["VfHistory"].keys())]
#print(xs)
ys = [a["VfHistory"][x][0]/1e6 for x in xs]
#print(ys)
m,b = np.polyfit(xsm, ys, 1)

print("% VfHistory m", m, "b", b, " with total time: (d-1)*m, b negl")

for fn in sorted(a.keys(), key=lambda x: a[x][128][0], reverse=True):
    mark="+" #only marks,mark="+mark+",
    if fn not in colors:
        #print("missing", fn)
        continue
    print("\\addplot[", colors[fn],",error bars/.cd,y dir=both ,y explicit] coordinates {")
    last = 1
    lastd = 1
    for deg in sorted(a[fn].keys()):
        el = a[fn][deg]
        print(f"({deg},{el[0]/1000000}) +- (0,{el[1]/1000000})  %{el[0]/1e6/last} ,  {el[0]/1e6/last / lastd}")
        lastd = el[0]/1e6/last
        last = el[0]/1e6
    print("};")
    print("\\addlegendentry{"+fn+"};")
