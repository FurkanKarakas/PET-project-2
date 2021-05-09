# %%
# Imports
import pandas as pd
import grid
from matplotlib import pyplot as plt
from mpl_toolkits.axes_grid1 import make_axes_locatable
from colorsys import hsv_to_rgb
import numpy as np


# %%
# Helper Classes

class User:
    def __init__(self, ip, queries, home, work, lunch, sports, social):
        self.ip = ip
        self.queries = queries
        self.home = home
        self.work = work
        self.lunch = lunch
        self.sports = sports
        self.social = social

    def plot(self):
        plt.plot(self.queries.lat, self.queries.lon, zorder=0)
        plt.scatter(self.queries.lat, self.queries.lon,
                    c=self.queries.timestamp % 24, cmap="hsv", vmin=0, vmax=24)  # type:ignore

        plt.plot([self.home.lat], [self.home.lon], color=(
            1, 0, 0), marker="*", markersize=20, zorder=1)
        plt.plot([self.work.lat], [self.work.lon], color=(
            0, 1, 0), marker="*", markersize=20, zorder=1)

        plt.colorbar()
        plt.title(self.ip)
        plt.show()


# %%
class PoiWeighter:
    def __init__(self, name, poi_types, peak_center, peak_narrowness, min_weight):
        self.name = name
        self.poi_types = poi_types
        self.weight_fun = lambda x: np.sin(
            (x - 12 - peak_center) * np.pi/24) ** peak_narrowness * (1-min_weight) + min_weight


weighters = [
    PoiWeighter(
        "home",
        ["appartment_block", "villa"],
        0, 2, 1/4
    ),
    PoiWeighter(
        "work",
        ["office", "laboratory", "company"],
        12, 4, 0
    ),
    PoiWeighter(
        "lunch",
        ["restaurant", "cafeteria"],
        12, 100, 0
    ),
    PoiWeighter(
        "sports",
        ["gym", "dojo"],
        16, 20, 1/4
    ),
    PoiWeighter(
        "social",
        ["restaurant", "cafeteria", "bar", "club"],
        22, 20, 0
    )
]


# %%
def subtraction_matrix(v1, v2):
    v1 = v1.repeat(len(v2)).reshape(len(v1), len(v2))
    v2 = v2.repeat(len(v1)).reshape(len(v2), len(v1)).T
    return v1 - v2


# %%
# Load Data
queries = pd.read_csv("queries.csv", sep=" ")
queries["cell_id"] = queries.apply(
    lambda l: grid.location_to_cell_id(l.lat, l.lon), axis=1)
queries["time_of_day"] = queries.apply(lambda l: l.timestamp % 24, axis=1)

pois = pd.read_csv("pois.csv", sep=" ")
pois["cell_id"] = pois.apply(
    lambda l: grid.location_to_cell_id(l.lat, l.lon), axis=1)

for weighter in weighters:
    queries[f"weight_{weighter.name}"] = weighter.weight_fun(
        queries.time_of_day)

# %%
# Calculate Distances from each query to each poi
delta_lat = subtraction_matrix(
    queries.lat.to_numpy(),
    pois.lat.to_numpy()
)

delta_lon = subtraction_matrix(
    queries.lon.to_numpy(),
    pois.lon.to_numpy()
)

# Distances in degrees
distances = np.sqrt(delta_lat**2 + delta_lon**2)

# Scores: distance 0 -> score 1, distance 100 -> score 0.25
quarter_distance = 100  # At what distance (m) the score should be 0.25
scores = 1/(1 + distances * (78348/quarter_distance))**2

# %%
users = pd.DataFrame()
#poi_scores = {str(poi_type): scores[:, pois.poi_type == poi_type] for poi_type in pois.poi_type.unique()}
# Instantiate classes
for ip, user_data in queries.groupby("ip_address"):
    user_scores = scores[user_data.index]
    user_scored_pois = pois.copy()
    topscorers = {}
    for weighter in weighters:
        weights = weighter.weight_fun(
            user_data.time_of_day).to_numpy().reshape(-1, 1)
        weighted_pois = pd.concat(
            user_scored_pois[user_scored_pois.poi_type == poi_type] for poi_type in weighter.poi_types)
        weighted_scores = user_scores[:, weighted_pois.index] * weights
        weighted_pois[f"score"] = weighted_scores.sum(axis=0) / len(user_data)
        best_index = weighted_pois.score.idxmax()
        topscorers[weighter.name] = weighted_pois.loc[best_index]

    user = User(ip, user_data, topscorers["home"], topscorers["work"],
                topscorers["lunch"], topscorers["sports"], topscorers["social"])
    print(ip)
    user.plot()
# %%
# server.closest(46.50005085562444, 6.583769105491683, "gym", 10)
# %%
