# CS-523 Project 2 Part 1: Attribute-Based Credentials

This is the README.md file for the first part of the second project of the Advanced Topics in Privacy Enhancing Technologies class in Spring 2021.

## Authors

[Furkan Karakaş](mailto:furkan.karakas@epfl.ch)

[Pascal Andreas Schärli](mailto:pascal.scharli@epfl.ch)

## Overview

This project consists of the implementation of 2 parts:

1. **credential.py**: This is the main file for the implementations of the attribute-based credentials. We followed the implementation details in the handout `ABC_guide.pdf`. We created classes to implement issuing and verifying the credentials. We also designed a class called `FiatShamirProof`. The client needs to create a non-interactive zero-knowledge proof with Fiat-Shamir heuristic during the user commitment step.

2. **stroll.py**: This is the file for integrating our implementations to the Docker network. The files `client.py` and `server.py` use the functions defined in this file in order to setup the Docker network and the client and server can communicate with each other by means of the API present in this file. We did not change the original skeleton of this file.

## Tests

We wrote several test scenarios to check the correctness of our implementations in the two files mentioned above. The tests can be found in the files `test_credential.py` and `test_stroll.py`. In order to run the tests, please issue the following command:

```bash
python3 -m pytest <NAME OF THE FILE>
```

where `<NAME OF THE FILE>` is one of the two files mentioned above. As failure paths, we included tests in these files where we try to verify the signature with a wrong public key or we try to verify a malicious signature with the correct public key.

## Benchmarking

We wrote performance tests in terms of communication and computational costs using the `pytest-benchmark` software. We did performance tests of the system for different number of user attributes, in particular, when the user subscribed for 5, 10, 20, 50, 100, and 500 attributes.
