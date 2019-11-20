import json

res1 = "./resForCAIDA.txt"
res2 = "./resForHGC.txt"

def func(dataFile):
	with open(res1, "r") as f:
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

res = func(res1)
print res
