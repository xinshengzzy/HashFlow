import json
from simulators.CHashFlow import CHashFlow
from simulators.AHashFlow import AHashFlow

src1 = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.json"
src2 = "/home/zongyi/traces/HGC.20080415000.json"
dst1 = "./resForCAIDA.txt"
dst2 = "./resForHGC.txt"
thresh = 10

if __name__ == "__main__":
	memory = 0.25*1024*1024
	thresh = 5
	ahf = AHashFlow(memory)
	chf = CHashFlow(memory)
	with open(src1, "r") as f:
		pkts = json.load(f)

	with open(dst1, "w") as f:
		f.write("#n_pkts\tahf.hh_are\tchf.hh_are\tahf.hh_f1score\tchf.hh_f1score\n")
	flows = dict()
	count = 0
	for k in range(40):
		for i in range(500000):
			p = pkts[count][1]
			count = count + 1
			if p not in flows:
				flows[p] = 0
			flows[p] = flows[p] + 1
			ahf.receive_pkt(p)
			chf.receive_pkt(p)
		l = [str(count)]
		l.append(str(ahf.hh_are(flows, thresh)))
		l.append(str(chf.hh_are(flows, thresh)))
		l.append(str(ahf.hh_f1score(flows, thresh)))
		l.append(str(chf.hh_f1score(flows, thresh)))
		line = "\t".join(l) + "\n"
		with open(dst1, "a") as f:
			f.write(line)

