import random


class User:
    def __init__(self, user_id):
        self.user_id = user_id
        self.voting_token = None


class Ballot:
    def __init__(self, ballot_id, choice):
        self.ballot_id = ballot_id
        self.choice = choice


def create_voting_token(voter):
    voter.voting_token = random.randint(1000, 9999)

    print("Voting token created")
    print("Token:", voter.voting_token)


def submit_ballot(voter, token, choice):

    if voter.voting_token == token:

        ballot = Ballot(1, choice)

        print("Ballot accepted")
        print("Choice:", ballot.choice)

        voter.voting_token = None

        print("Voting token removed")

        return ballot

    else:
        print("Invalid voting token")
        return None
