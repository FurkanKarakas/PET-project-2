# %%
from scapy.all import rdpcap, IP, Raw
from matplotlib import pyplot as plt
import numpy as np
import os
from scipy.ndimage import gaussian_filter1d


#%%
def get_peaks(volume, timestamps, window=0.5):
    timestamps_in_np = (np.array(timestamps_in) -  first) / (last - first)
    active = []
    sums = []
    for i in range(len(timestamps)):
        while len(active) > 0 and timestamps[i] > timestamps[active[0]] + window:
            active = active[1:]
        active.append(i)
        sums.append(sum(volume_in[j]/(1+timestamps[i]-timestamps[j]) for j in active))
    plt.plot(timestamps_in_np, sums)
    peaks = []
    for i in range(1, len(sums)-1):
        if sums[i-1] < sums[i] and sums[i+1] < sums[i]:
            peaks.append((i, sums[i]))
    return peaks

#%%
def get_peaks2(volume, normalized_timestamps, n_samples=100, sigma=0.02):
    x = np.arange(0, 1, 1/n_samples)
    sampled = [volume[np.argmin(np.abs(normalized_timestamps-i))] for i in x]
    filtered = gaussian_filter1d(sampled, sigma*n_samples)
    print(len(filtered))
    plt.plot(x, filtered*100)
    peaks = []
    for i in range(1, len(filtered)-1):
        if filtered[i-1] < filtered[i] and filtered[i+1] < filtered[i]:
            peaks.append((x[i], filtered[i]))
    return peaks


# %%
local_ip = "172.18.0.2"
for file in sorted(os.listdir("data")):
    if file.startswith("cell-012"):
        path = os.path.join("data", file)
        packets = rdpcap(path)

        volume_in = []
        timestamps_in = []

        for packet in packets:
            if IP in packet and Raw in packet:
                if packet[IP].dst == "172.18.0.2":
                    volume_in.append(len(packet[Raw]))
                    timestamps_in.append(packet.time)

        first = min(timestamps_in)
        last = max(timestamps_in)

        volume_in = np.array(volume_in)
        normalized_timestamps = (np.array(timestamps_in) -  first) / (last - first)
        
        accum_in = np.add.accumulate(volume_in)
        plt.plot(normalized_timestamps, accum_in, color="green")
        peaks = get_peaks2(volume_in, normalized_timestamps)
        for (i, s) in peaks:
            plt.scatter([i], [s], color="red")
        print(len(peaks))
        plt.show()

# %%

path = os.path.join("data", "cell-001_001.pcap")
packets = rdpcap(path)

volume_in = []
timestamps_in = []

for packet in packets:
    if IP in packet and Raw in packet:
        if packet[IP].dst == "172.18.0.2":
            volume_in.append(len(packet[Raw]))
            timestamps_in.append(packet.time)

first = min(timestamps_in)
last = max(timestamps_in)

volume_in = np.array(volume_in)
accum_in = np.add.accumulate(volume_in)
timestamps_in_np = (np.array(timestamps_in) -  first) / (last - first)
#%%
timestamp_diffs = timestamps_in_np[1:]-timestamps_in_np[:-1]
n_buckets = 20
max_size = 500000
histogram = np.zeros(n_buckets)
for a, t in zip(accum_in[1:], timestamp_diffs):
    histogram[int(n_buckets * a/max_size)] += t
print(histogram)

#%%
n_samples = 50
sampled = [volume_in[np.argmin(np.abs(timestamps_in_np-i))] for i in np.arange(0, 1, 1/n_samples)]
filtered = gaussian_filter1d(sampled, 2/n_samples)
plt.plot(sampled)
plt.plot(filtered)

#%%
get_peaks(volume_in, timestamps_in)

#%%
plt.plot(timestamps_in, volume_in)
#%%
sp = np.fft.fft(accum_in)
freq = np.fft.fftfreq(len(timestamps_in_np))
plt.plot(freq, sp.real, color="red")
plt.plot(freq, sp.imag, color="blue")

#%%
levels = []
last = True
thresh = 0.1
for i in range(1, len(timestamps_in)):
    delta = timestamps_in[i]-timestamps_in[i-1]
    if delta > thresh:
        if not last:
            levels.append(accum_in[i])
            plt.plot([0, 1], [accum_in[i], accum_in[i]], color='black')
        last = True
    else:
        last = False

#%%
derivative = []
for i in range(1, len(accum_in)):
    derivative.append((accum_in[i]-accum_in[i-1])/(timestamps_in[i]-timestamps_in[i-1]))

derivative = np.array(derivative, dtype=np.float)*0.005
plt.plot(timestamps_in[1:], derivative, color="red")
plt.plot(timestamps_in_np, accum_in, color="green")
plt.show()
    # %%
