import numpy as np
import sys
from scapy.all import IP, Raw, rdpcap, TCP

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score


def classify(train_features, train_labels, test_features, test_labels):
    """Function to perform classification, using a
    Random Forest.

    Reference: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html

    Args:
        train_features (numpy array): list of features used to train the classifier
        train_labels (numpy array): list of labels used to train the classifier
        test_features (numpy array): list of features used to test the classifier
        test_labels (numpy array): list of labels (ground truth) of the test dataset

    Returns:
        predictions: list of labels predicted by the classifier for test_features

    Note: You are free to make changes the parameters of the RandomForestClassifier().
    """

    # Initialize a random forest classifier. Change parameters if desired.
    clf = RandomForestClassifier()
    # Train the classifier using the training features and labels.
    clf.fit(train_features, train_labels)
    # Use the classifier to make predictions on the test features.
    predictions = clf.predict(test_features)

    return predictions


def perform_crossval(features, labels, folds=10):
    """Function to perform cross-validation.
    Args:
        features (list): list of features
        labels (list): list of labels
        folds (int): number of fold for cross-validation (default=10)
    Returns:
        You can modify this as you like.

    This function splits the data into training and test sets. It feeds
    the sets into the classify() function for each fold.

    You need to use the data returned by classify() over all folds
    to evaluate the performance.
    """

    kf = StratifiedKFold(n_splits=folds)
    labels = np.array(labels)
    features = np.array(features)
    accuracy_scores = list()

    for train_index, test_index in kf.split(features, labels):
        X_train, X_test = features[train_index], features[test_index]
        y_train, y_test = labels[train_index], labels[test_index]
        predictions = classify(X_train, y_train, X_test, y_test)
        accuracy_scores.append(accuracy_score(y_test, predictions))

    print(f"{folds}-fold accuracy scores: {accuracy_scores}")
    print(f"Mean accuracy score: {np.mean(accuracy_scores)}")
    print(f"Std accuracy score: {np.std(accuracy_scores)}")

    ###############################################
    # TODO: Write code to evaluate the performance of your classifier
    ###############################################


def load_data():
    """Function to load data that will be used for classification.

    Args:
        You can provide the args you want.
    Returns:
        features (list): the list of features you extract from every trace
        labels (list): the list of identifiers for each trace

    An example: Assume you have traces (trace1...traceN) for cells with IDs in the
    range 1-N.

    You extract a list of features from each trace:
    features_trace1 = [f11, f12, ...]
    .
    .
    features_traceN = [fN1, fN2, ...]

    Your inputs to the classifier will be:

    features = [features_trace1, ..., features_traceN]
    labels = [1, ..., N]

    Note: You will have to decide what features/labels you want to use and implement
    feature extraction on your own.
    """

    ###############################################
    # TODO: Complete this function.
    ###############################################

    features = []
    labels = []
    r = np.linspace(0, 1000, 50)

    for cell_id in range(1, 101):
        print(f"Cell ID: {cell_id}")
        for i in range(29):
            count_incoming = 0
            count_outgoing = 0
            raw_incoming = 0
            raw_outgoing = 0
            i_str = '0'*(3-len(str(i)))+str(i)
            cell_id_str = '0'*(3-len(str(cell_id)))+str(cell_id)
            try:
                scapy_cap = rdpcap('data/cell-'+cell_id_str+'_'+i_str+'.pcap')
            except:
                print(
                    f"File {'data/cell-'+cell_id_str+'_'+i_str+'.pcap'} is not found. Skipping to the next cell...")
                break
            for packet in scapy_cap:
                if Raw in packet and IP in packet and TCP in packet:
                    # if not len(packet[Raw]) <= 4200:
                    #    continue
                    if packet[IP].src == "172.18.0.2":
                        count_outgoing += 1
                        raw_outgoing += len(packet[Raw])
                    elif packet[IP].dst == "172.18.0.2":
                        count_incoming += 1
                        raw_incoming += len(packet[Raw])

            labels.append(cell_id)
            features.append([count_outgoing, raw_outgoing, count_incoming,
                            raw_incoming])

    return features, labels


def main():
    """Please complete this skeleton to implement cell fingerprinting.
    This skeleton provides the code to perform classification
    using a Random Forest classifier. You are free to modify the
    provided functions as you wish.

    Read about random forests: https://towardsdatascience.com/understanding-random-forest-58381e0602d2
    """

    features, labels = load_data()
    perform_crossval(features, labels, folds=10)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
