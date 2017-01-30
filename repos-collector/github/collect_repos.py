import csv
from github import BadCredentialsException
from github import Github
import sys
from tqdm import tqdm
import json

# get GitHub credentials from config.json file
with open('config.json') as cf:
    data = json.load(cf)


def get_repositories():
    print('Collecting information from GitHub repositories...')

    # save information about repositories in the csv file
    with open('rc_' + sys.argv[1] + '.csv', 'w', newline='') as rf:
        a = csv.writer(rf, delimiter=',')
        i = 0

        # for each repository
        for repo in tqdm(g.get_repos(since=0)):
            i += 1
            # stop the search
            if i > int(sys.argv[1]):
                break
            else:
                # save repository info in the file
                a.writerow([str(repo.owner.login), repo.name])

    print('Process Finished! Collect your csv file from the source folder.')


try:

    # authentication for Github API
    g = Github(data['github']['username'], data['github']['token'])

    # check arguments
    if (len(sys.argv) > 2
        or sys.argv[1].isdigit() is False):
        print("Usage: collect_repos.py <int_number>")
        sys.exit(0)

    # function to get repositories
    get_repositories()

except BadCredentialsException as e:
    print('\nSomething went wrong, check your GitHub informations on the config.json file.')
    sys.exit(0)
