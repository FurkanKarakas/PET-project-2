# Internal Deadlines

## Now - 2021-05-01

- Finish part 1: attribute-based credentials
  - TODO: README

## 2021-05-01 - 2021-05-14

- Finish Part 2: (de)anonymization of user trajectories
  - IP still leaked, how bad is it?
  - Attack:
    - Can you breach the privacy of simulated users in the dataset? Can you figure out where some users live, work, or what are their interests?
    - What other information can you infer?
      - Friends
      - Someones Cheating on their Partner?
      - Group by hours, location, ip address

  - Defense:
    - User should always gets information he wants
    - Client Side Caching
    - Don't send coordinates, just send grid ID
      - No gain in sending it, no loss in not sending it
    - Add noise:
      - Maybe don't necessarily return the grid we're in, but one close to it, with exponentially decreasing probability (differential privacy)
      - Also send other requests along the ones from the user
        - When?
          - Always send bogus requests -> Drains users battery (utility)
          - When the app is opened send requests -> Server knows when user is using app (privacy)
          - Only send bogus requests at the same time legit requests are sent -> Server knows exact time of requests (Privacy)
        - Where?
          - Random walk


- Start Part 3: network traffic data collection
    - Start data collection
    - How to intercept data? Tor? On program level?
    - https://moodle.epfl.ch/mod/forum/discuss.php?d=58825 -> Server sends all POI, regardless of the subscription...
      - -> So just response size can tell a lot about the cell grid already?

## 2021-05-15 - 2021-05-28
- Finish Part 3: network traffic fingerprinting

## 2021-05-29 - 2021-06-04

- Finishing Touches & Submission
