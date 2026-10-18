"""Counting: small examples worked out by hand (Yufei)."""
from app.security.counting import count_house, lot_order

A, B, C, D = "avery", "blake", "casey", "dana"


# --- Y18 ---

def test_a_candidate_with_a_majority_wins_in_the_first_round():
    ballots = [[A, B]] * 6 + [[B, A]] * 3 + [[C]] * 1
    result = count_house(ballots, [A, B, C])
    assert result["elected"] == [A]
    assert result["rounds"] == [{A: 6, B: 3, C: 1}]


def test_preferences_flow_on_when_the_lowest_is_excluded():
    """Worked by hand: 10 ballots.
    Round 1: A 4, B 3, C 2, D 1 -> nobody over 5, exclude D (D's ballot goes to C)
    Round 2: A 4, B 3, C 3      -> exclude ... B and C tie on 3; the lot decides
    """
    ballots = ([[A]] * 4 + [[B, C]] * 3 + [[C, B]] * 2 + [[D, C, B]])
    result = count_house(ballots, [A, B, C, D], seed="contest-1")
    assert result["rounds"][0] == {A: 4, B: 3, C: 2, D: 1}
    assert result["rounds"][1] == {A: 4, B: 3, C: 3}
    # whichever of B and C is excluded, their ballots go to the other: 6 beats 4
    assert result["elected"] in ([B], [C])
    assert result["rounds"][2][A] == 4 and sum(result["rounds"][2].values()) == 10


def test_exhausted_ballots_drop_out_of_the_count():
    ballots = [[A]] * 3 + [[B]] * 2 + [[C]] * 2  # nobody gives a second preference
    result = count_house(ballots, [A, B, C], seed="x")
    assert result["elected"] == [A]
    assert sum(result["rounds"][-1].values()) < 7  # some ballots exhausted
