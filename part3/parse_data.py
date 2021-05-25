# %%
from scapy.all import rdpcap, IP, Raw
from matplotlib import pyplot as plt
import numpy as np


# %%
local_ip = "172.18.0.2"
packets = rdpcap("data/cell-001_001.pcap")

# %%
volume_in = []
timestamps_in = []

volume_out = []
timestamps_out = []

for packet in packets:
    if IP in packet and Raw in packet:
        if packet[IP].dst == "172.18.0.2":
            volume_in.append(len(packet[Raw]))
            timestamps_in.append(packet.time)
        elif packet[IP].src == "172.18.0.2":
            volume_out.append(len(packet[Raw]))
            timestamps_out.append(packet.time)

volume_in = np.array(volume_in)
timestamps_in = np.array(timestamps_in)
volume_out = np.array(volume_out)
timestamps_out = np.array(timestamps_out)

# %%
plt.clf()
accum_in = np.add.accumulate(volume_in)
accum_out = np.add.accumulate(volume_out)
plt.plot(timestamps_out, accum_out, color="blue")
plt.plot(timestamps_in, accum_in, color="green")
plt.show()