import csv
import json
import os
from github import BadCredentialsException
from github import Github
import sys
import re
from tqdm import tqdm
import time
import git


# get GitHub credentials from config.json file
with open('config.json') as cf:
    data = json.load(cf)

# needs to be improved

injection = re.compile('injection| xss |cross.*(site|zone) script|script injec');
csrf = re.compile('(cross.*site request forgery| csrf |sea.*surf| xsrf |one.*click attack|session riding)');
dns = re.compile('(dos |(denial.*of.*service) | ddos)');
auth = re.compile('(unauthor.*(access|contr))');
misc = re.compile('((fix|found).* (sec.* bug|vulnerab|problem|issue))|((secur|vulnerab).* problem)|secur|bug|vulnerab|problem');
fileName = sys.argv[1].split('.')[0]


def mine_repos(user, repos):
    # path for the new file
    path = 'db/'+repos+'/'+sys.argv[1]+'/'

    # create output file if not exists
    os.makedirs(os.path.dirname(path), exist_ok=True)

    #repo = git.Repo.init(g.get_user(user).get_repo(repos).url)
    repo = git.Repo.clone_from(g.get_user(user).get_repo(repos).clone_url, 'repos/' + user+'_'+repos + '/', branch='master')

    commits = list(repo.iter_commits());

    #with open(path+'/head/','wb') as fp:
    #    repo.archive(fp)
    n = 0;
    for c in tqdm(commits):

        if sys.argv[1] == "misc":
            check = misc.search(c.message)
        elif sys.argv[1] == "injection":
            check = injection.search(c.message)

        parents = list(c.parents)
        if check is not None and len(parents) > 0:
            n += 1;
            vulPath = path + 'vuln'+str(n)+'/';
            os.makedirs(os.path.dirname(vulPath), exist_ok=True)

            print(c)

            repo.head.reference = c
            with open(vulPath + 'Vfix.tar', 'wb') as fp:
                repo.archive(fp)

            if len(parents) == 1:
                vulParent = parents[0]
                print(parents[0])
            elif len(parents) > 1:
                vulParent = parents[1]
                print(parents[1])

            repo.head.reference = vulParent;

            with open(vulPath + 'Vvul.tar', 'wb') as fp:
                repo.archive(fp)

            print('-----------')

            for d in c.diff(vulParent, create_patch=True):
                print(d)

try:

    # authentication for Github API
    g = Github(data['github']['username'], data['github']['token'])

    # check arguments
    if (len(sys.argv) > 3
        or isinstance(sys.argv[2], str) is False):
        print("Usage: repos_miner.py <class> <filename>")
        sys.exit(0)

    with open(sys.argv[2], 'r') as rf:
        r = csv.reader(rf, delimiter=',')
        start = time.clock()
        for (user, repos) in r:
            # mine each repository
            mine_repos(user, repos)
        stop = time.clock()
        timeSpent = stop-start;
        print("Time Spent: " + str(timeSpent))

    print("Process finished! Check results folder.")

except BadCredentialsException as e:
    print('\nSomething went wrong, check your GitHub informations on the config.json file.')
    sys.exit(0)
