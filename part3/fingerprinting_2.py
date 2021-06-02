import numpy as np
import sys
import os
from scapy.all import IP, Raw, rdpcap, TCP
from tqdm import tqdm

from sklearn.ensemble import RandomForestClassifier
from sklearn import svm
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
    
    # Initialize a random forest classifier. Change parameters if desired.
    #clf = svm.SVC(kernel='rbf')
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
        a = accuracy_score(y_test, predictions)
        print(a)
        accuracy_scores.append(a)

    print(f"{folds}-fold accuracy scores: {accuracy_scores}")
    print(f"Mean accuracy score: {np.mean(accuracy_scores)}")
    print(f"Std accuracy score: {np.std(accuracy_scores)}")

    ###############################################
    # TODO: Write code to evaluate the performance of your classifier
    ###############################################

def shorten_to_smallest(x):
    for i in range(x.shape[1]):
        if np.any(np.all(x[:,i:]==0, axis=1)):
            return x[:,:i]
    return x

def load_data():#i):
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

    features = [
        "basic_counts",
        "packet_accums",
        "size_markers"
        #"size_markers",
        #"number_markers",
        #"occuring_incoming_packet_sizes",
        #"occuring_outgoing_packet_sizes",
        #"percentage_incoming",
        #"number_of_packets"
    ]

    # used_features = []
    # for j in range(len(features)):
    #     if 1<<j & i != 0:
    #         used_features.append(features[j])

    # features = used_features

    print("Using features", features)
    features_folder = "parsed_features"
    y = np.load(os.path.join(features_folder, "y.npy"))

    Xs = [np.load(os.path.join(features_folder, f"X-{f}.npy")) for f in features]
    
    total_width = sum(x.shape[1] for x in Xs)
    X = np.ndarray((len(y), total_width))
    i = 0
    for x in Xs:
        end = i + x.shape[1]
        X[:,i:end] = x
        i = end

    X=np.nan_to_num(X)
    print(X.shape)

    # Shuffle
    np.random.seed(0)
    random_indices = np.random.permutation(np.arange(len(X)))
    X = X[random_indices]#[:2000]
    y = y[random_indices]#[:2000]

    return X, y

def main():
    """Please complete this skeleton to implement cell fingerprinting.
    This skeleton provides the code to perform classification
    using a Random Forest classifier. You are free to modify the
    provided functions as you wish.

    Read about random forests: https://towardsdatascience.com/understanding-random-forest-58381e0602d2
    """

    features, labels = load_data()#i)
    perform_crossval(features, labels, folds=10)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
