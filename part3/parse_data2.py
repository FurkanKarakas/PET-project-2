from scapy.all import rdpcap, IP, Raw
from matplotlib import pyplot as plt
import numpy as np
import os
from ipaddress import ip_address
from pprint import pprint
from tqdm import tqdm
import random


class Measurement:
    def __init__(self, packets, cell_id, measurement_id, filters, feature_functions):
        self.cell_id = cell_id
        self.measurement_id = measurement_id
        self.filters = filters
        self.feature_functions = feature_functions
        self.features = {
            fun.__name__: fun(filter(self.filter, packets)) for fun in self.feature_functions
        }

    def filter(self, packet):
        return all(map(lambda f: f(packet), self.filters))

    def __repr__(self):
        return f"{self.__class__.__name__}(cell_id={self.cell_id})"


def get_measurements(folder, filters, feature_functions):
    # for file in tqdm(random.sample(os.listdir(folder),100), "extracting features"):
    for file in tqdm(sorted(os.listdir(folder)), "extracting features"):
        path = os.path.join(folder, file)
        cell_id, measurement_id = tuple(
            map(int, file.split("-")[1].split(".")[0].split("_")))
        yield Measurement(rdpcap(path), cell_id, measurement_id, filters, feature_functions)


def get_direction(packet):
    if ip_address(packet[IP].src).is_private:
        return "OUT"
    else:
        return "IN"


def round_to_increment(num, increment):
    return int(round(num / increment)*increment)


def packet_lengths(packets):
    return [len(p) for p in packets]


def packet_accums(packets):
    out = []
    accum = 0
    for p in packets:
        accum += len(p)
        out.append(accum)
    return out

def accum_in(packets):
    out = []
    accum = 0
    for p in packets:
        if get_direction(p) == "IN":
            accum += len(p)
        out.append(accum)
    return out

def accum_out(packets):
    out = []
    accum = 0
    for p in packets:
        if get_direction(p) == "OUT":
            accum += len(p)
        out.append(accum)
    return out


def size_markers(packets, rounding_increment=1):
    direction = None
    accum = 0
    out = []
    for packet in packets:
        if direction is None:
            direction = get_direction(packet)
        new_direction = get_direction(packet)
        if new_direction != direction:
            out.append(round_to_increment(accum, rounding_increment))
            accum = 0
        accum += len(packet)
    return [len(out)] + out


"""
groups={1: [1],
        2: [3, 4, 5],
        3: [6, 7, 8],
        4: [9, 10, 11, 12, 13]
        }
"""


def number_markers(packets, groups={1: [1],
                                    2: [3, 4, 5],
                                    3: [6, 7, 8],
                                    4: [9, 10, 11, 12, 13]
                                    }):
    direction = None
    accum = 0
    out = []
    for packet in packets:
        if direction is None:
            direction = get_direction(packet)
        new_direction = get_direction(packet)
        if new_direction != direction:
            # for key, group in groups.items():
            #     if accum in group:
            #         out.append(key)
            #         break
            # else:
            #     out.append(key+1)
            out.append(accum)
            accum = 0
        accum += 1
    return [len(out)] + out


def total_transmitted_bytes(packets, rounding_increment=1):
    return [round_to_increment(sum(len(packet) for packet in packets), rounding_increment)]


def occuring_incoming_packet_sizes(packets):
    sizes = {}
    for packet in packets:
        if get_direction(packet) == "IN":
            size = len(packet)
            sizes[size] = sizes.get(size, 0) + 1
    return sizes


def occuring_outgoing_packet_sizes(packets):
    sizes = {}
    for packet in packets:
        if get_direction(packet) == "OUT":
            size = len(packet)
            sizes[size] = sizes.get(size, 0) + 1
    return sizes


def percentage_incoming(packets):
    incoming = 0
    total = 0
    for packet in packets:
        if get_direction(packet) == "IN":
            incoming += 1
        total += 1
    return [incoming / total]


def number_of_packets(packets):
    return [len(list(packets))]

    count_incoming = 0
    count_outgoing = 0
    raw_incoming = 0
    raw_outgoing = 0


def basic_counts(packets):
    count_incoming = 0
    count_outgoing = 0
    raw_incoming = 0
    raw_outgoing = 0
    for packet in packets:
        if get_direction(packet) == "IN":
            count_incoming += 1
            raw_incoming += len(packet[IP])
        else:
            count_outgoing += 1
            raw_outgoing += len(packet[IP])
    return [count_outgoing, raw_outgoing, count_incoming, raw_incoming]


def pad_lists_to_numpy(lists):
    max_len = max(len(l) for l in lists)
    out = np.zeros(shape=(len(lists), max_len))
    for i, l in enumerate(lists):
        out[i, :len(l)] = l
    return out


def pad_dicts_to_numpy(dicts):
    keys = set()
    for d in dicts:
        for key in d.keys():
            keys.add(key)

    keys = list(keys)
    out = np.zeros(shape=(len(dicts), len(keys)))

    for i, d in enumerate(dicts):
        for k, v in d.items():
            out[i][keys.index(k)] = v

    return out


if __name__ == "__main__":
    FILTERS = [
        lambda packet: IP in packet,
        lambda packet: Raw in packet,
        lambda packet: len(packet) != 54,
        lambda packet: ip_address(packet[IP].src).is_private != ip_address(
            packet[IP].dst).is_private
    ]

    FEATURES = [
        accum_in,
        accum_out
        #basic_counts,
        #packet_lengths,
        #packet_accums,
        #size_markers,
        #number_markers,
        #occuring_incoming_packet_sizes,
        #occuring_outgoing_packet_sizes,
        #percentage_incoming,
        #number_of_packets
    ]

    measurements = list(get_measurements("data.total", FILTERS, FEATURES))
    features = {}
    for measurement in tqdm(measurements, "collecting features"):
        for feature_name, values in measurement.features.items():
            feature_collection = features.get(feature_name, [])
            feature_collection.append(values)
            features[feature_name] = feature_collection

    out_folder = "parsed_features"
    if not os.path.exists(out_folder):
        os.makedirs(out_folder)

    for feature_name, value_list in tqdm(list(features.items()), "saving features"):
        if isinstance(value_list[0], dict):
            out = pad_dicts_to_numpy(value_list)
        else:
            out = pad_lists_to_numpy(value_list)
        np.save(os.path.join(out_folder, f"X-{feature_name}.npy"), out)
    
    y = np.array([m.cell_id for m in measurements])
    np.save(os.path.join(out_folder, "y.npy"), y)
