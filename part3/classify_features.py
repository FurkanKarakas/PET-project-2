from sklearn import svm
from sklearn.model_selection import KFold
import numpy as np
import os

if __name__ == "__main__":
    features_folder = "parsed_features"
    X = np.load(os.path.join(features_folder, "X.npy"))
    y = np.load(os.path.join(features_folder, "X.npy"))



    accuracies = cross_val_score(estimator=classifier, X=X, y=y, cv = 10)    