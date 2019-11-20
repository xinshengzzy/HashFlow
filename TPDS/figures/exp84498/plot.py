import json
import matplotlib.pyplot as plt
import matplotlib
import matplotlib
#import np
from matplotlib.patches import Ellipse

font = {'size':18}
matplotlib.rc('font', **font)


caida1 = "./resForCAIDA1.txt"
caida2 = "./resForCAIDA2.txt"
hgc1 = "./resForHGC1.txt"
hgc2 = "./resForHGC2.txt"

def func(dataFile):
	with open(dataFile, "r") as f:
		l = json.load(f)
	res = [0]*101	
	for item in l:
		for i in range(100, -1, -1):
			if item <= i*0.01:
				res[i] = res[i] + 1
			else:
				break
	for i in range(101):
		res[i] = float(res[i])/len(l)
	return res

if __name__ == "__main__":
	caida1 = func(caida1)
	caida2 = func(caida2)
	hgc1 = func(hgc1)
	hgc2 = func(hgc2)
	plt.figure(1)
	idx = []
	for i in range(11):
		idx.append(i*0.1)
	plt.xticks(range(0, 101, 10), ("0", "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1.0"))
	plt.plot(range(101), caida1, label = "CAIDA1", marker = "x")
	plt.plot(range(101), caida2, label = "CAIDA2", marker = "x")
	plt.plot(range(101), hgc1, label = "HGC1", marker = "^")
	plt.plot(range(101), hgc2, label = "HGC2", marker = "^")
	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.xlabel("x-Dist Coefficient")
	plt.ylabel("CDF")
	plt.savefig("cdf.pdf", bbox_inches = "tight")
	plt.savefig("cdf.png", bbox_inches = "tight")

