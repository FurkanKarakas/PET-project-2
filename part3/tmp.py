import os
import shutil

inputs = ["data", "data.bak", "data.bak2"]
output = "data.total"

for folder in inputs:
    for file in os.listdir(folder):
        path = os.path.join(folder, file)
        if os.path.getsize(path) > 50000:
            cell_id, measurement_id = tuple(map(int, file.split("-")[1].split(".")[0].split("_")))
            index = 0
            out_path = os.path.join(output, f"cell-{cell_id:03}_{index:03}.pcap")
            while os.path.exists(out_path):
                index += 1
                out_path = os.path.join(output, f"cell-{cell_id:03}_{index:03}.pcap")
            print(out_path)
            shutil.copyfile(path, out_path)
