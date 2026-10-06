# r16_voter_eligibility.py


class User:
    def __init__(self, user_id, is_enrolled, electorate):
        self.user_id = user_id
        self.is_enrolled = is_enrolled
        self.electorate = electorate


class Election:
    def __init__(self, election_id, is_active, electorate):
        self.election_id = election_id
        self.is_active = is_active
        self.electorate = electorate


def check_voter_eligibility(voter, election):

    if voter.is_enrolled == False:
        print("Voter is not enrolled")
        print("Eligibility decision: REJECTED")
        return False

    else:
        if election.is_active == False:
            print("Voting period is not active")
            print("Eligibility decision: REJECTED")
            return False

        else:
            if voter.electorate != election.electorate:
                print("Voter is not eligible for this electorate")
                print("Eligibility decision: REJECTED")
                return False

            else:
                print("Voter is eligible")
                print("Eligibility decision: ACCEPTED")
                return True



