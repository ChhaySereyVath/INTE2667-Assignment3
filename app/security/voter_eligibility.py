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


# Test 1 - eligible voter
voter1 = User(1, True, "Bruce")
election1 = Election(1, True, "Bruce")

check_voter_eligibility(voter1, election1)


print("----------------")


# Test 2 - voter not enrolled
voter2 = User(2, False, "Bruce")

check_voter_eligibility(voter2, election1)


print("----------------")


# Test 3 - wrong electorate
voter3 = User(3, True, "Casey")

check_voter_eligibility(voter3, election1)


print("----------------")


# Test 4 - election closed
election2 = Election(2, False, "Bruce")

check_voter_eligibility(voter1, election2)