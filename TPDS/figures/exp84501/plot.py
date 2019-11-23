import json
import matplotlib.pyplot as plt
import matplotlib
import matplotlib
#import np
from matplotlib.patches import Ellipse

font = {'size':18}
matplotlib.rc('font', **font)

src = "./resForCAIDA.txt"

def func(src):
	npkts = []
	ahf_hhare = []
	chf_hhare = []
	ahf_hhf1score = []
	chf_hhf1score = []
	with open(src, "r") as f:
		for line in f:
			if "#" == line[0]:
				continue
			items = line.split("\t")
			npkts.append(int(items[0]))	
			ahf_hhare.append(float(items[1]))
			chf_hhare.append(float(items[2]))
			ahf_hhf1score.append(float(items[3]))
			chf_hhf1score.append(float(items[4]))
	return npkts, ahf_hhare, chf_hhare, ahf_hhf1score, chf_hhf1score

if __name__ == "__main__":
	npkts, ahf_hhare, chf_hhare, ahf_hhf1score, chf_hhf1score = func(src)
	plt.figure(1)
#	plt.title("x=0.95")
#	plt.xticks(range(0, 101, 10), ("0", "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1.0"))
	plt.plot(range(1, 41), ahf_hhare, label = "AHashFlow", marker = "x")
	plt.plot(range(1, 41), chf_hhare, label = "CHashFlow", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 4)
	plt.xlabel("X500000 pkts")
	plt.ylabel("ARE")
	plt.savefig("hh_are.pdf", bbox_inches = "tight")
	plt.savefig("hh_are.png", bbox_inches = "tight")

	plt.figure(2)
#	plt.title("x=0.95")
#	plt.xticks(range(0, 101, 10), ("0", "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1.0"))
	plt.plot(range(1, 41), ahf_hhf1score, label = "AHashFlow", marker = "x")
	plt.plot(range(1, 41), chf_hhf1score, label = "CHashFlow", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 1)
	plt.xlabel("X500000 pkts")
	plt.ylabel("F1 Score")
	plt.savefig("hh_f1score.pdf", bbox_inches = "tight")
	plt.savefig("hh_f1score.png", bbox_inches = "tight")
	
