#%%
from parse_pcap import *
from matplotlib import pyplot as plt
import matplotlib

#%%
FILTERS = [
    lambda packet: IP in packet,
    lambda packet: Raw in packet,
    lambda packet: len(packet) != 54,
    lambda packet: ip_address(packet[IP].src).is_private != ip_address(
        packet[IP].dst).is_private
]

pcap_file = "data.total/cell-001_000.pcap"
packets = filter(lambda packet: all(f(packet)
                                    for f in FILTERS), rdpcap(pcap_file))

#%%
max_size=1000000
n_buckets=70

volume = []
timestamps = []
for packet in packets:
    volume.append(len(packet))
    timestamps.append(packet.time)
volume = np.array(volume)
accum = np.add.accumulate(volume)
timestamps = np.array(timestamps)
timestamps -= min(timestamps)

timestamp_diffs = timestamps[1:]-timestamps[:-1]
histogram = np.zeros(n_buckets)
for a, t in zip(accum[1:], timestamp_diffs):
    bucket = int(n_buckets * a/max_size)
    if bucket >= len(histogram):
        bucket = len(histogram)-1
    histogram[bucket] += t

# %%
# Plots for report
font = {'family' : 'normal',
        'weight' : 'bold',
        'size'   : 40}
matplotlib.rcParams.update({'font.size': 16})

# Accumulated size
plt.title("Packet Size Accumulations")
plt.xlabel("Time [s]")
plt.ylabel("Accumulated Size [kB]")
plt.xlim(0, 10)
plt.ylim(0, 450)

plt.plot(timestamps, accum/1000, linewidth=3, color="black")
plt.show()
plt.clf()

# Plots for report
# Size Histogram
plt.title("Size Histogram")
plt.xlabel("Total Time [s]")
plt.ylabel("Accumulated Size [kB]")
plt.xlim(0, 2)
plt.ylim(0, 450)

plt.plot(histogram, np.arange(0, max_size, max_size/n_buckets)/1000, linewidth=3, color="black")
plt.show()
plt.clf()
# %%
