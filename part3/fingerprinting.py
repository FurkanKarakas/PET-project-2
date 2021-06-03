import numpy as np
import sys
import os
from scapy.all import IP, Raw, rdpcap, TCP
from tqdm import tqdm
import itertools

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
 
    This function splits the data into training and test sets. It feeds
    the sets into the classify() function for each fold.

    You need to use the data returned by classify() over all folds
    to evaluate the performance.
 
    Args:
        features (list): list of features
        labels (list): list of labels
        folds (int): number of fold for cross-validation (default=10)
    Returns:
        You can modify this as you like.
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
        accuracy_scores.append(a)

    return np.mean(accuracy_scores), np.std(accuracy_scores)

def load_data(features):
    """Function to load data that will be used for classification.

    Args:
        features (list): A list of string names, for the features that should be loaded.
    Returns:
        X (list): the list of features you extract from every trace
        y (list): the list of identifiers for each trace
    """

    # Load identifiers
    y = np.load(os.path.join("parsed_features", "y.npy"))

    # Load all features
    Xs = [np.load(os.path.join("parsed_features",
                               f"X-{f}.npy")) for f in features]

    # Merge features to single array
    total_width = sum(x.shape[1] for x in Xs)
    X = np.ndarray((len(y), total_width))
    i = 0
    for x in Xs:
        end = i + x.shape[1]
        X[:, i:end] = x
        i = end

    # Remove nans
    X = np.nan_to_num(X)

    # Shuffle
    np.random.seed(0) # we decided to seed permutation to get reproducible results
    random_indices = np.random.permutation(np.arange(len(X)))
    X = X[random_indices]
    y = y[random_indices]

    return X, y

def main():
    """Tests performance all possible combinations of up to 3 different feature sets, using 10-folds cross validation
    """
    tested_features = [
        "size_histogram",
        "accum_in",
        "accum_out",
        "basic_counts",
        "packet_lengths",
        "packet_accums",
        "size_markers",
        "number_markers",
        "occuring_incoming_packet_sizes",
        "occuring_outgoing_packet_sizes",
        "percentage_incoming",
        "number_of_packets"
    ]

    combinations = []
    for i in range(1, 4):
        combinations += list(itertools.combinations(tested_features, i))
    scores = []
    pbar = tqdm(combinations)
    for features in pbar:
        pbar.set_description(", ".join(features))
        X, y = load_data(features)
        accuracy, std = perform_crossval(X, y, folds=10)
        scores.append((accuracy, std, features))

    print("Ranking:")
    for i, (accuracy, std, features) in enumerate(sorted(scores, reverse=True)):
        print(f"{i+1:>3}. acc:{accuracy:.5f}, std:{std:.5f}, {','.join(features)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
