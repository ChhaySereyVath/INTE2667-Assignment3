# r17_prevent_double_voting.py


class User:
    def __init__(self, user_id):
        self.user_id = user_id

        # Record whether the voter has already voted
        # in each ballot type
        self.has_voted_house = False
        self.has_voted_senate = False


def submit_vote(voter, ballot_type):

    # House ballot
    if ballot_type == "House":

        if voter.has_voted_house == True:
            print("House vote rejected")
            print("Reason: voter has already submitted a House vote")
            return False

        else:
            print("House vote accepted")

            voter.has_voted_house = True

            print("has_voted_house changed to True")
            return True


    # Senate ballot
    elif ballot_type == "Senate":

        if voter.has_voted_senate == True:
            print("Senate vote rejected")
            print("Reason: voter has already submitted a Senate vote")
            return False

        else:
            print("Senate vote accepted")

            voter.has_voted_senate = True

            print("has_voted_senate changed to True")
            return True


    # Invalid ballot type
    else:
        print("Vote rejected")
        print("Reason: invalid ballot type")
        return False


