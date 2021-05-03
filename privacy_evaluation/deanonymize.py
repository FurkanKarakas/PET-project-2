import pandas
import grid
from matplotlib import pyplot as plt
from mpl_toolkits.axes_grid1 import make_axes_locatable
from colorsys import hsv_to_rgb


def plot_user(title, user_data):
    plt.clf()
    plt.plot(user_data.lat, user_data.lon, zorder=0)
    plt.scatter(user_data.lat, user_data.lon, c=user_data.timestamp %
                24, cmap="hsv", vmin=0, vmax=24)
    plt.colorbar()
    plt.title(title)
    plt.show()


if __name__ == "__main__":
    queries = pandas.read_csv("queries.csv", sep=" ")

    cell_ids = queries.apply(
        lambda l: grid.location_to_cell_id(l.lat, l.lon), axis=1)
    queries["cell_id"] = cell_ids

    queries_by_user = queries.groupby("ip_address")

    possible_subscriptions = queries_by_user.poi_type_query.unique()

    for ip, user_data in queries_by_user:
        plot_user(ip, user_data)
