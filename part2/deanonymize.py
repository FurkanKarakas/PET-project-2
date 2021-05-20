# %%
# Imports
import pandas as pd
import grid
from matplotlib import pyplot as plt
from mpl_toolkits.axes_grid1 import make_axes_locatable
from colorsys import hsv_to_rgb
import numpy as np
import datetime
import json

# %%
# Helper Classes


class User:
    def __init__(self, ip, home, work, sports):
        self.ip = ip
        self.home = home
        self.work = work
        self.sports = sports
        self.meetups = {}
        self.work_colleagues = set()
        self.living_with = set()

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
        "sports",
        ["gym", "dojo"],
        16, 20, 1/4
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
queries["time_of_day"] = queries.apply(lambda l: l.timestamp % 24, axis=1)

pois = pd.read_csv("pois.csv", sep=" ")

for weighter in weighters:
    queries[f"weight_{weighter.name}"] = weighter.weight_fun(
        queries.time_of_day)

# %%
# Maps coordinates to poi_id
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

# See https://www.desmos.com/calculator/dlzawknavh
# Scores: distance 0 -> score 1, distance 100 -> score 0.25
# At what distance (m) the score should be 0.25 (since all pois are exact matches I set this very small)
quarter_distance = 5
scores = 1/(1 + distances * (78348/quarter_distance))**2

# %%
# Plots for report
# Distance score
plt.title("Distance Score")
plt.xlabel("Distance [m]")
plt.ylabel("Score")
plt.xticks(range(11))
plt.xlim(0, 10)

plot_distances = np.arange(0, 11, 0.1)
plot_scores = 1/(1 + plot_distances/quarter_distance)**2
plt.plot(plot_distances, plot_scores, color="black")
plt.show()
plt.clf()

# Time score
plt.title("Time Score")
plt.xlabel("Time [h]")
plt.ylabel("Score")
plt.xticks(range(0, 25, 3))
plt.xlim(0, 24)

plot_times = np.arange(0, 25, 0.1)
styles = ['solid', 'dotted', 'dashed']
for style, weighter in zip(styles, weighters):
    plt.plot(plot_times, weighter.weight_fun(plot_times),
             label=weighter.name.title(), color='black', linestyle=style)
plt.legend(loc="upper right")

# %%
users = {}

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
        if weighted_pois.score[best_index] > 0:
            topscorers[weighter.name] = weighted_pois.poi_id[best_index]
        else:
            topscorers[weighter.name] = None
    users[ip] = User(
        ip,
        topscorers["home"],
        topscorers["work"],
        topscorers["sports"],
    )

# %% Get Work and Home colleagues
for idx1, (ip1, user1) in enumerate(users.items()):
    for idx2, (ip2, user2) in enumerate(users.items()):
        if idx1 < idx2:
            if user1.home == user2.home:
                user1.living_with.add(ip2)
                user2.living_with.add(ip1)
            if user1.work == user2.work:
                user1.work_colleagues.add(ip2)
                user2.work_colleagues.add(ip1)

# %% Social events
min_score = 0.1
query_index, poi_index = np.where(scores >= min_score)
visits = {}
for (_, query), (_, poi) in zip(queries.iloc[query_index].iterrows(), pois.iloc[poi_index].iterrows()):
    if poi.poi_id not in visits:
        visits[poi.poi_id] = {}
    if query.ip_address not in visits[poi.poi_id]:
        visits[poi.poi_id][query.ip_address] = []
    visits[poi.poi_id][query.ip_address].append(query.timestamp)

for poi, visitors in visits.items():
    for user, timestamps in visitors.items():
        visits[poi][user] = np.array(timestamps)

# %%
max_time = 0.25
for poi, visitors in visits.items():
    for idx1, (user1, timestamps1) in enumerate(visitors.items()):
        for idx2, (user2, timestamps2) in enumerate(visitors.items()):
            if idx1 > idx2:
                ts_indices_1, ts_indices_2 = np.where(
                    subtraction_matrix(timestamps1, timestamps2) < max_time)
                if user2 not in users[user1].meetups:
                    users[user1].meetups[user2] = []
                if user1 not in users[user2].meetups:
                    users[user2].meetups[user1] = []

                for ts1 in sorted(set(timestamps1[ts_indices_1])):
                    users[user1].meetups[user2].append((ts1, poi))
                for ts2 in sorted(set(timestamps2[ts_indices_2])):
                    users[user2].meetups[user1].append((ts2, poi))

# %%
# Create social graph
node_names = [user.ip for user in users.values()]
social_graph = {"nodes": [], "links": []}
edges = set()
for user_ip in node_names:
    user = users[user_ip]
    social_graph["nodes"].append({
        "group": int(user.work),
        "name": user.ip
    })

    for other_ip, meetups in user.meetups.items():
        if len(meetups) > 10:
            a, b = sorted([user_ip, other_ip])
            if (a, b) not in edges:
                edges.add((a, b))

                if other_ip in user.living_with:
                    color= "red"
                elif other_ip in user.work_colleagues:
                    color="blue"
                else:
                    if len(meetups) < 15:
                        continue
                    color="green"

                social_graph["links"].append({
                    "source": node_names.index(user_ip),
                    "target": node_names.index(other_ip),
                    "distance": (50/len(meetups))**2,
                    "color": color
                })

with open("graph/data.json", "w+") as f:
    json.dump(social_graph, f, indent=1)

print("dumped")

# %%

day_0 = datetime.datetime(2021, 5, 3).timestamp()


def ts_to_string(ts):
    day = ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"][int((ts//24) % 7)]
    hours = int(ts % 24)
    minutes = int(60*(ts-int(ts)))
    return f"{day} {hours}:{minutes}"


def summarize(user, cluster_time=2):
    out = [f"Summary of User with IP {user.ip}:"]
    home = pois[pois.poi_id == user.home].iloc[0]
    out.append("- Home:")
    out.append(f"    - Living in a {home.poi_type}")
    out.append(f"    - Location: ({home.lat}, {home.lon})")
    if len(user.living_with) > 0:
        out.append(f"    - Together with {', '.join(user.living_with)}")
    else:
        out.append(f"    - Alone.")

    work = pois[pois.poi_id == user.work].iloc[0]
    out.append("- Work:")
    out.append(f"    - Working at a {work.poi_type}")
    out.append(f"    - Location: ({work.lat}, {work.lon})")
    if len(user.work_colleagues) > 0:
        out.append(f"    - Together with {', '.join(user.work_colleagues)}")
    else:
        out.append(f"    - Alone.")

    out.append("- Sports:")
    if user.sports is None:
        out.append("    - Does not do sports")
    else:
        sports = pois[pois.poi_id == user.sports].iloc[0]
        out.append(f"    - Most often goes to {sports.poi_type}")
        out.append(f"    - Location: ({sports.lat}, {sports.lon})")

    out.append("- Meetups outside of work/home:")
    sorted_meetups = sorted(user.meetups.items(),
                            key=lambda x: len(x[1]), reverse=True)

    for other_ip, ts_pois in sorted_meetups:
        if other_ip not in user.work_colleagues and other_ip not in user.living_with and len(ts_pois) > 0:
            out.append(f"    - {other_ip}:")
            last_ts = 0
            last_poi_id = None
            for ts, poi_id in sorted(ts_pois):
                if poi_id != user.work and poi_id != user.home and poi_id != last_poi_id or ts-last_ts > cluster_time:
                    time_string = datetime.datetime.fromtimestamp(
                        day_0 + ts*3600).strftime("%a %d.%m %H:%M")
                    poi_type = pois[pois.poi_id == poi_id].iloc[0].poi_type
                    out.append(
                        f"        - {poi_type} (id:{poi_id}) at {time_string}")
                last_ts = ts
                last_poi_id = poi_id
    return "\n".join(out)


# %%
for ip, user in users.items():
    print(summarize(user))
# %%
