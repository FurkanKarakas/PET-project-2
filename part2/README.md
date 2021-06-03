# CS-523 Project 2 Part 2: (De)Anonymization of User Trajectories

This is the README.md file for the second part of the second project of the Advanced Topics in Privacy Enhancing Technologies class in Spring 2021.

## Authors

[Furkan Karakaş](mailto:furkan.karakas@epfl.ch)

[Pascal Andreas Schärli](mailto:pascal.scharli@epfl.ch)

## Overview

The attack is implemented in the file `deanonymize.py` to infer sensitive information from the queries stored in the file `queries.csv` which were issued by the users of the app. The details of the functions used in that file can be found in the corresponding section in the report. A defense mechanism is implemented in the Jupyter notebook `defense.ipynb`. Again, the details of the defense mechanism can be found in the corresponding section in the report. As helper functions, we defined new functions in the file `grid.py` to process the cell grids in the map more conveniently.

This directory also contains a folder `graph`, which contains some helper scripts that were used to draw the social graph used in the report. The graph was drawn using the Javascript library [d3js](d3js.org), and the data.json file is created from `deanonymize.py`. The graph can be generated using any webserver, such as `python3 -m http.server 8080`. Using a webserver instead of just opening the `index.html` file in a browser is necessary, as the `data.json` file could not be loaded otherwise due to the Same Origin Policy.
