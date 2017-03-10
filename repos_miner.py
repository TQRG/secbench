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

injection = re.compile(' xss |cross.*(site|zone) script|script injec|injection|(full)?.*path.*disclosure');
csrf = re.compile('(cross.*site req.* forgery| csrf |sea.*surf| xsrf |one.*click attack|session riding)');
pathtrav = re.compile('((path|dir.*) traver.*|(dot-dot-slash|directory traversal|directory climbing|backtracking).*(attack|vuln))');
dos = re.compile('( dos |((distributed)? denial.*of.*service) | ddos | deadlocks)');

bufover = re.compile('buff.* overflow')
nullp = re.compile('null pointers');
resl = re.compile('res.* leaks');
sha1 = re.compile('sha 1|sha1|sha-1|(sha-1|sha 1|sha1) collision');
ml = re.compile('mem.* (leak|alloc)|fix malloc');
hl = re.compile('hand.* (leak|alloc)');
encryp = re.compile('encryp.* (bug|vulnerab|problem|defect|warning|issue|weak|attack|flaw|fault|error)')
auth = re.compile('(unauthor.*(access|contr))|vuln.* auth|plaintext pass.*|auth.* bypass|sess.* fixation|weak pass.* verification');
misc = re.compile('((fix|found|prevent|protect)?.*sec.* (bug|vulnerab|problem|defect|warning|issue|weak|attack|flaw|fault|error)(fix|found|prevent|protect)?.*)|vulnerab|attack');

fileName = sys.argv[1].split('.')[0]

def check_if_dir_exists(path):
    d=os.path.dirname(path);
    if not os.path.exists(d):
        os.makedirs(d)


def make_tarfile(output_filename, source_dir):
    with tarfile.open(output_filename, "w") as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))

def mine_repos(user, repos):
    # path for the new file
    path = 'db/'+user+'_'+repos+'/'+sys.argv[1]+'/'
    print(path)
    global vuls;

    # create output file if not exists
    try:
        os.makedirs(os.path.dirname(path))
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    repo = git.Repo.clone_from(g.get_user(user).get_repo(repos).clone_url, 'repos/' + user+'_'+repos + '/', branch='master')

    commits = list(repo.iter_commits());

    n = 0;
    for c in tqdm(commits):

        # classes
        if sys.argv[1] == "misc":
            check = misc.search(c.message)
        elif sys.argv[1] == "injec":
            check = injection.search(c.message)
        elif sys.argv[1] == "csrf":
            check = csrf.search(c.message)
        elif sys.argv[1] == "dos":
            check = dos.search(c.message)
        elif sys.argv[1] == "auth":
            check = auth.search(c.message)
        elif sys.argv[1] == "ml":
            check = ml.search(c.message)
        elif sys.argv[1] == "pathtrav":
            check = pathtrav.search(c.message)
        elif sys.argv[1] == "encrypt":
            check = encryp.search(c.message)



        parents = list(c.parents)
        if check is not None and len(parents) > 0:
            n += 1;
            vuls+=1;

            vulPath = path + 'vuln'+str(n)+'/';
            os.makedirs(os.path.dirname(vulPath))
            repo.head.reference = c
            with open(vulPath + 'Vfix.tar', 'wb') as vf:
                repo.archive(vf)

            if len(parents) == 1:
                vulParent = parents[0]
            elif len(parents) > 1:
                vulParent = parents[1]

            repo.head.reference = vulParent;

            with open(vulPath + 'Vvul.tar', 'wb') as vv:
                repo.archive(vv)

            a.writerow([vuls,n,
                        path,
                        sys.argv[1],
                        c,
                        vulParent,
                        '',
                        '',
                        '',
                        '',
                        '',
                        '',
                        ''])

            diff = c.diff(vulParent, create_patch=True)

            # a few diffs give an empty array (fix this)
            if len(diff) > 0:
                for f in diff:
                    #print(f)
                    if f.a_blob is not None:
                        pathA=vulPath + 'Vdiff/added/' + f.a_path;
                        check_if_dir_exists(pathA)
                        f.a_blob.stream_data(open(pathA, 'wb'))
                    if f.b_blob is not None:
                        pathB=vulPath + 'Vdiff/deleted/' + f.b_path;
                        check_if_dir_exists(pathB)
                        f.b_blob.stream_data(open(pathB, 'wb'))
                make_tarfile(vulPath + 'Vdiff.tar',vulPath + 'Vdiff')
                shutil.rmtree(vulPath + 'Vdiff')

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

    rf = open(sys.argv[2], 'r')
    r = csv.reader(rf, delimiter=',')
    res = open("results.txt", "w+")

    cfi = open('results.csv','a')
    a = csv.writer(cfi, delimiter=',')
    a.writerow(['id','idf',
                'path',
                'type',
                'sha',
                'sha-p',
                'line',
                'TP',
                'FP',
                'FN',
                'other',
                'result',
                'observations'])


    start = time.clock()
    vuls=0;

    for (user, repos, check) in r:
    # mine each repository
        if check == 'x':
            mine_repos(user, repos)
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
