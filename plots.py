from glob import glob
import json
from collections import defaultdict

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
          "VfHistory": "dotted",
          "VfKeyGen": "black",
          "Decrypt": "black"}

for fn in a:
    mark="+" #only marks,mark="+mark+",
    if fn not in colors:
        #print("missing", fn)
        continue
    print("\\addplot[", colors[fn],",error bars/.cd,y dir=both ,y explicit] coordinates {")
    for deg in sorted(a[fn].keys()):
        el = a[fn][deg]
        print(f"({deg},{el[0]/1000000}) +- (0,{el[1]/1000000})")
    print("};")
    print("\\addlegendentry{"+fn+"};")
