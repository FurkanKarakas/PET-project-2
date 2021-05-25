# CS-523 Project 2 Part 3: Cell Fingerprinting via Network Traffic Analysis

This is the README.md file for the third part of the second project of the Advanced Topics in Privacy Enhancing Technologies class in Spring 2021.

## Authors

[Furkan Karakaş](mailto:furkan.karakas@epfl.ch)

[Pascal Andreas Schärli](mailto:pascal.scharli@epfl.ch)

## Data collection

In order to collect data, we used the script `collect_data.py` which uses `tcpdump` in the Docker container to sniff on the client's network traffic while requesting a location server by using the Tor network. We captured packets for every grid from 1 to 100 with 29 samples. For convenience, we did not include the captured files in this repository. They can be accessed via [this link](https://polybox.ethz.ch/index.php/s/cyhYyJPbq7oW2VO).

## Network traffic analysis

The Jupyter notebook `processing.ipynb` contains code snippets to play with the captured files by using the software `scapy`. The file `parse_data.py` contains useful functions to visualize the packets in the captured files. The classifier and the extracted features reside in `fingerprinting.py`. Please have a look at the function `load_data` to see which features we used in our classifier.
