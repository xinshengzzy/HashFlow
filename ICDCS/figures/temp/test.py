filename = "./caida_distribution.txt"
with open(filename, "r") as f:
    line = f.read()
    items = line.split(" ")
    flow_size_dist = [float(item) for item in items]
    volume_dist = [0]
    for i in range(1, len(flow_size_dist)):
        ratio = flow_size_dist[i] - flow_size_dist[i-1]
        volume = i*ratio
        volume_dist.append(volume_dist[i-1] + volume)
    for i in range(len(volume_dist)):
        volume_dist[i] = volume_dist[i]/volume_dist[-1]
    flow_size = 11
    print("flow size:", flow_size)
    print("flow size distribution:", 1.0 - flow_size_dist[flow_size])
    print ("volume distribution:", 1.0 - volume_dist[flow_size])
