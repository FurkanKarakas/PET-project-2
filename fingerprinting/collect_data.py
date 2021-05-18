#!/usr/bin python3
# Captures pcap files of queries
# Run in docker container within the /client directory
# The client should be registered to restaurant, bar, sushi
import subprocess
import os
import time
import random

class Capture:
    def __init__(self, name):
        index = 0
        self.out_path = os.path.join("fingerprinting/data", f"{name}_{index:03}.pcap")
        while os.path.exists(self.out_path):
            index += 1
            self.out_path = os.path.join("fingerprinting/data", f"{name}_{index:03}.pcap")            
        self.process = None

    def __enter__(self):
        self.process = subprocess.Popen(["tcpdump", "-w", self.out_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def __exit__(self, *args):
        self.process.terminate()
        self.process.wait()

def query(grid, queries):
    query_args = [arg for argtuple in zip(["-T"]*len(queries), queries) for arg in argtuple]
    #print("executing", " ".join(["python3", "part1/client.py", "grid", str(grid)] + query_args + ["-t"]))
    subprocess.call(["python3", "/client/part1/client.py", "grid", str(grid)] + query_args + ["-t"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

if __name__ == "__main__":
    query_types = ["restaurant", "bar", "sushi"]
    while True:
        for cell_id in range(1, 101):
            print("Querying cell id", cell_id)
            n_queries = random.randint(1, len(query_types))
            queries = random.sample(query_types, n_queries)
            with Capture(f"cell-{cell_id:03}") as c:
                query(cell_id, queries)