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
import shutil
import tarfile
import os.path as osp


# get GitHub credentials from config.json file
with open('config.json') as cf:
    data = json.load(cf)

# needs to be improved

injection = re.compile('injection| xss |cross.*(site|zone) script|script injec');
csrf = re.compile('(cross.*site request forgery| csrf |sea.*surf| xsrf |one.*click attack|session riding)');
dns = re.compile('(dos |(denial.*of.*service) | ddos | deadlocks)');
ml = re.compile('mem.* leaks');
auth = re.compile('(unauthor.*(access|contr))');
misc = re.compile('((fix|found|prevent|protect)?.*sec.* (bug|vulnerab|problem|defect|warning|issue|weak|attack|flaw|fault|error)(fix|found|prevent|protect)?.*)|secur|vulnerab|attack');

fileName = sys.argv[1].split('.')[0]


def make_tarfile(output_filename, source_dir):
    with tarfile.open(output_filename, "w") as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))

def mine_repos(user, repos):
    # path for the new file
    path = 'db/'+user+'_'+repos+'/'+sys.argv[1]+'/'

    # create output file if not exists
    os.makedirs(os.path.dirname(path), exist_ok=True)
    repo = git.Repo.clone_from(g.get_user(user).get_repo(repos).clone_url, 'repos/' + user+'_'+repos + '/', branch='master')

    commits = list(repo.iter_commits());

    cfi = open(path+'commits_info.csv','w', newline='')
    a = csv.writer(cfi, delimiter=',')

    n = 0;
    for c in tqdm(commits):

        if sys.argv[1] == "misc":
            check = misc.search(c.message)
        elif sys.argv[1] == "injection":
            check = injection.search(c.message)
        elif sys.argv[1] == "csrf":
            check = csrf.search(c.message)


        parents = list(c.parents)
        if check is not None and len(parents) > 0:
            print('-----------------------')

            n += 1;
            print('vuln'+str(n));

            vulPath = path + 'vuln'+str(n)+'/';
            os.makedirs(os.path.dirname(vulPath), exist_ok=True)
            repo.head.reference = c
            with open(vulPath + 'Vfix.tar', 'wb') as vf:
                repo.archive(vf)

            if len(parents) == 1:
                vulParent = parents[0]
            elif len(parents) > 1:
                vulParent = parents[1]

            print(c)
            print(vulParent)
            print(parents)

            repo.head.reference = vulParent;

            with open(vulPath + 'Vvul.tar', 'wb') as vv:
                repo.archive(vv)

            a.writerow([str(n), c, vulParent, c.message])

            diff = c.diff(vulParent, create_patch=True)

            # a few diffs give an empty array (fix this)
            if len(diff) > 0:
                for f in diff:
                    if f.a_blob is not None:
                        os.makedirs(os.path.dirname(vulPath + 'Vdiff/added/' + f.a_path), exist_ok=True)
                        f.a_blob.stream_data(open(vulPath + 'Vdiff/added/'+f.a_path, 'wb'))
                    if f.b_blob is not None:
                        os.makedirs(os.path.dirname(vulPath + 'Vdiff/deleted/' + f.b_path), exist_ok=True)
                        f.b_blob.stream_data(open(vulPath+ 'Vdiff/deleted/'+ f.b_path, 'wb'))
                make_tarfile(vulPath + 'Vdiff.tar',vulPath + 'Vdiff')
                shutil.rmtree(vulPath + 'Vdiff')
    print(n)
    if n == 0:
        shutil.rmtree(path)
    return n;


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
        res = open("results.txt", "w+")
        vuls = 0;
        start = time.clock()
        for (user, repos, check) in r:
        # mine each repository
            if check == 'x':
                vuls += mine_repos(user, repos)
                shutil.rmtree('repos/' + user+'_'+repos + '/')
        shutil.rmtree('repos/')
        stop = time.clock()
        timeSpent = stop-start;
        res.write("Time: %s" % timeSpent + "\n")
        res.write("NoVuls: %s" % vuls + " \n")


    print("Process finished! Check results folder.")

except BadCredentialsException as e:
    print('\nSomething went wrong, check your GitHub informations on the config.json file.')
    sys.exit(0)
