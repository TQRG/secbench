import csv
import json
import os
from github import BadCredentialsException
from github import Github
import sys
import re
from tqdm import tqdm
from datetime import datetime

# get GitHub credentials from config.json file
with open('config.json') as cf:
    data = json.load(cf)

# needs to be improved
secureReg = re.compile('((fix|found).* (bug|vulnerab|problem))|((secur|vulnerab).* problem)|secur|bug|vulnerab|problem')
fileName = sys.argv[1].split('.')[0]


def mine_repos(user, repos):
    # path for the new file
    path = 'vulFound/' + fileName + '/' + user + '_' + repos + '.csv'

    # create output file if not exists
    os.makedirs(os.path.dirname(path), exist_ok=True)

    # open new file
    with open(path, 'w', newline='') as vf:

        a = csv.writer(vf, delimiter=',')

        # get commits for each repository
        commits = g.get_user(user).get_repo(repos).get_commits(since=datetime(2000, 1, 1, 0, 0), until=datetime.now())

        # for each commit
        for c in commits:

            # check if the regular expression secureReg matches with the commit message
            check = secureReg.search(c.commit.message)

            # if check true
            if check:

                # write for the file the commit url and commit message
                a.writerow([c.commit.url, c.commit.message])

try:

    # authentication for Github API
    g = Github(data['github']['username'], data['github']['token'])

    # check arguments
    if (len(sys.argv) > 2
        or isinstance(sys.argv[1], str) is False):
        print("Usage: repos_miner.py <filename>")
        sys.exit(0)

    with open(sys.argv[1], 'r') as rf:
        r = csv.reader(rf, delimiter=',')
        for (user, repos) in tqdm(r):
            # mine each repository
            mine_repos(user, repos)

    print("Process finished! Check vulFounded folder.")

except BadCredentialsException as e:
    print('\nSomething went wrong, check your GitHub informations on the config.json file.')
    sys.exit(0)
