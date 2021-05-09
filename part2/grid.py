import bisect

# Grid parameters
# Top left corner of the area
MAP_LAT = 46.5
MAP_LON = 6.55

# Total area size
MAP_SIZE_LAT = 0.07
MAP_SIZE_LON = 0.10

# Number of cells
CELL_NUM_LAT = 10
CELL_NUM_LON = 10

# Grid lines
GRID_LAT_POINTS = [MAP_LAT + i * (MAP_SIZE_LAT / CELL_NUM_LAT)
                   for i in range(1, CELL_NUM_LAT + 1)]
GRID_LON_POINTS = [MAP_LON + i * (MAP_SIZE_LON / CELL_NUM_LON)
                   for i in range(1, CELL_NUM_LON + 1)]


def location_to_cell_id(lat, lon):
    """Get the grid cell ID for a given latitude and longitude."""
    if not (MAP_LAT <= lat < MAP_LAT + MAP_SIZE_LAT) or not (
        MAP_LON <= lon < MAP_LON + MAP_SIZE_LON
    ):
        raise ValueError("Out of area range.")

    i = bisect.bisect(GRID_LAT_POINTS, lat)
    j = bisect.bisect(GRID_LON_POINTS, lon)
    return i * CELL_NUM_LAT + j + 1


def location_to_cell_representative(lat, lon):
    """Get the grid cell representative coordinates for a given latitude and longitude."""
    if not (MAP_LAT <= lat < MAP_LAT + MAP_SIZE_LAT) or not (
        MAP_LON <= lon < MAP_LON + MAP_SIZE_LON
    ):
        raise ValueError("Out of area range.")

    i = bisect.bisect(GRID_LAT_POINTS, lat)
    j = bisect.bisect(GRID_LON_POINTS, lon)
    if i == 0 and j == 0:
        return (GRID_LAT_POINTS[0]+MAP_LAT)/2, (GRID_LON_POINTS[0]+MAP_LON)/2
    elif i == 0:
        return (GRID_LAT_POINTS[0]+MAP_LAT)/2, (GRID_LON_POINTS[j]+GRID_LON_POINTS[j-1])/2
    elif j == 0:
        return (GRID_LAT_POINTS[i]+GRID_LAT_POINTS[i-1])/2, (GRID_LON_POINTS[0]+MAP_LON)/2
    return (GRID_LAT_POINTS[i]+GRID_LAT_POINTS[i-1])/2, (GRID_LON_POINTS[j]+GRID_LON_POINTS[j-1])/2


def index_to_cell_representative(i, j):
    """Get the grid cell representative coordinates for given indices."""
    if i == 0 and j == 0:
        return (GRID_LAT_POINTS[0]+MAP_LAT)/2, (GRID_LON_POINTS[0]+MAP_LON)/2
    elif i == 0:
        return (GRID_LAT_POINTS[0]+MAP_LAT)/2, (GRID_LON_POINTS[j]+GRID_LON_POINTS[j-1])/2
    elif j == 0:
        return (GRID_LAT_POINTS[i]+GRID_LAT_POINTS[i-1])/2, (GRID_LON_POINTS[0]+MAP_LON)/2
    return (GRID_LAT_POINTS[i]+GRID_LAT_POINTS[i-1])/2, (GRID_LON_POINTS[j]+GRID_LON_POINTS[j-1])/2


def location_to_cell_indices(lat, lon):
    """Get the grid cell indices for a given latitude and longitude."""
    if not (MAP_LAT <= lat < MAP_LAT + MAP_SIZE_LAT) or not (
        MAP_LON <= lon < MAP_LON + MAP_SIZE_LON
    ):
        raise ValueError("Out of area range.")

    i = bisect.bisect(GRID_LAT_POINTS, lat)
    j = bisect.bisect(GRID_LON_POINTS, lon)
    return i+1, j+1
