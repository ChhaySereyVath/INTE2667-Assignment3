"""Counting (basic, as the brief allows): pure functions, no database, easy to test.

A ballot is a list of candidate ids, most preferred first.
- House: instant runoff (preferential). Count each ballot for its highest-ranked
  candidate still in the count; while nobody has more than half, exclude the lowest.
- Senate: simplified. The `seats` candidates with the most first preferences win
  (no quota or surplus transfers; listed as a limitation in the report).

Ties are settled by a "lot order": the candidates shuffled once with a seed (the
contest id). The same seed always gives the same order, so a recount always gives the
same result, and the order is returned so it can be published with the result.
"""
import random
from collections import Counter


def lot_order(candidates, seed):
    """A fixed, reproducible random order of the candidates, used only to break ties."""
    order = sorted(candidates)
    random.Random(seed).shuffle(order)  # nosec B311: a published lot, not a secret
    return order


def first_choices(ballots, continuing):
    """Each ballot counts for its highest preference that is still in the count."""
    tally = Counter({candidate: 0 for candidate in continuing})
    for ballot in ballots:
        for candidate in ballot:
            if candidate in continuing:
                tally[candidate] += 1
                break  # no continuing candidate left: the ballot is "exhausted"
    return tally


def count_house(ballots, candidates, excluded=(), seed=""):
    """Instant-runoff count for one seat. Returns the winner and every round."""
    order = lot_order(candidates, seed)
    continuing = set(candidates) - set(excluded)
    rounds = []
    while continuing:
        tally = first_choices(ballots, continuing)
        rounds.append(dict(tally))
        total = sum(tally.values())
        # most votes first; a tie goes to whoever comes earlier in the lot order
        ranked = sorted(continuing, key=lambda c: (-tally[c], order.index(c)))
        if len(continuing) == 1 or (total and tally[ranked[0]] * 2 > total):
            return {"elected": [ranked[0]], "rounds": rounds, "lot_order": order}
        continuing.discard(ranked[-1])  # exclude the lowest (on a tie, the latest in the lot)
    return {"elected": [], "rounds": rounds, "lot_order": order}


def count_senate(ballots, candidates, seats, excluded=(), seed=""):
    """First-preference count; the `seats` highest are elected."""
    order = lot_order(candidates, seed)
    continuing = set(candidates) - set(excluded)
    tally = first_choices(ballots, continuing)
    ranked = sorted(continuing, key=lambda c: (-tally[c], order.index(c)))
    return {"elected": ranked[:seats], "rounds": [dict(tally)], "lot_order": order}
