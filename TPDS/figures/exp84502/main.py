import json
src1 = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.json"
src2 = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-130000.UTC.anon.json"
src3 = "/home/zongyi/traces/HGC.20080415000.json"
src4 = "/home/zongyi/traces/HGC.20080415001.json"
dst = "./res.json"
n_pkts = 5000000

def func(src, n_pkts):
	with open(src, "r") as f:
		pkts = json.load(f)
	flows = dict()
	for i in range(n_pkts):
		p = pkts[i][1]
		if p not in flows:
			flows[p] = {"begin": i, "end": 0, "cnt": 0}
		flows[p]["end"] = i
		flows[p]["cnt"] = flows[p]["cnt"] + 1
	span_max = 0
	for key, value in flows.items():
		temp = value["end"] - value["begin"] + 1
		if temp > span_max:
			span_max = temp
	spans = dict()	
	for key, value in flows.items():
		temp = value["end"] - value["begin"] + 1
		if temp not in spans:
			spans[temp] = 0
		spans[temp] = spans[temp] + 1
	idx = []
	cdf = []
	pre = 0
	for i in range(1, span_max + 1):
		if i in spans:
			idx.append(i)
			temp = pre + spans[i]
			pre = temp
			cdf.append(temp)
	for i in range(len(cdf)):
		cdf[i] = cdf[i]/float(pre)
	print len(cdf)
	return [idx, cdf]

if __name__ == "__main__":
	spans1 = func(src1, n_pkts)
	spans2 = func(src2, n_pkts)
	spans3 = func(src3, n_pkts)
	spans4 = func(src4, n_pkts)
	res = [spans1, spans2, spans3, spans4]
	with open(dst, "w") as f:
		json.dump(res, f)
