import csv
import json
import os
import sys
import re
from tqdm import tqdm
import time
import git
import shutil
import os.path as osp
from utils import *
import requests
from connect import *
from db_op import *

V_CLASS = sys.argv[1]

#Top 10 OSWAP 2013
# injection (sql,ldap,xpath,xquery,xml,html,os commands).
injec = re.compile('(sql|ldap|xpath|xquery|queries|xml|html|(shell|os|oper.* sys|command|cmd)).*injec|(fix|prevent|found|protect).* injec|injec.* (fix|prev|found|protect)');
# broken authentication and access control
auth = re.compile('(brute.*force|dict|sess.*hijack|broken auth).* (prevent|protect|fix)|(prevent|protect|fix).* (brute.*force|dict|sess.* hijack|broken auth)|(unauthor.*(access|contr))|vuln.* auth|plaintext pass.*|auth.* bypass|sess.* fixation|weak pass.* verif');
# xss
xss = re.compile('fix.* ( xss |cross.*(site|zone) script)|crlf injec|http resp.* split|(reflect|stored|dom).*xss|xss.*(reflect|stored|dom)|xss (vuln|prob|solution)| xss')
# csrf
csrf = re.compile('(cross.*site.*(req|ref).*forgery| csrf |sea.*surf| xsrf |(one.*click|autom).*attack|sess.*riding|conf.*deput)');
# insecure direct object references
# security misconfiguration
# sensitive data exposure
# missing function level access control
# using known vulnerable components
# unvalidated redirects and forwards

# path traversal
pathtrav = re.compile('((path|dir.*) traver.*|(dot-dot-slash|directory traversal|directory climbing|backtracking).*(attack|vuln))');
# denial of service
dos = re.compile('( dos |((distributed)? denial.*of.*service)| ddos |deadlocks)')
# sha-1 collision
sha1 = re.compile('(sha-1|sha 1|sha1) collision')
# misc
misc = re.compile('(fix|found|prevent|protect).*sec.*(bug|vulnerab|problem|defect|warning|issue|weak|attack|flaw|fault|error)|sec.* (bug|vulnerab|problem|defect|warning|issue|weak|attack|flaw|fault|error).* (fix|found|prevent|protect)|vulnerab|attack');
# memory leaks
ml = re.compile('mem.* leak|(fix|inc).* mem.* alloc')

bufover = re.compile('buff.* overflow')
fpd = re.compile('(full)? path discl')
nullp = re.compile('null pointers')
resl = re.compile('res.* leaks')
hl = re.compile('hand.* (leak|alloc)')
encryp = re.compile('encryp.* (bug|vulnerab|problem|defect|warning|issue|weak|attack|flaw|fault|error)')


def add_blobs(diff,vulPath):
    for f in diff:
        if f.a_blob is not None:
            pathA=vulPath + 'Vdiff/added/' + f.a_path
            check_if_dir_exists(pathA)
            try:
                f.a_blob.stream_data(open(pathA, 'wb'))
            except Exception as ex:
                print('Ex:', ex)
        if f.b_blob is not None:
            pathB=vulPath + 'Vdiff/deleted/' + f.b_path
            check_if_dir_exists(pathB)
            try:
                f.b_blob.stream_data(open(pathB, 'wb'))
            except Exception as ex:
                print('Ex:', ex)

def save_results(conn, start, datetime,vuls):
    stop = time.time()
    t = stop-start
    conn.incr('stats:experiment:n')
    add_experiment(conn, datetime, V_CLASS, t, vuls)
    if os.path.exists('repos/'):
        remove_dir('repos')
    if os.path.exists('db/'):
        remove_dir('db')

def mine_repos(user, repos, br):

    global conn, g , V_CLASS, bucket

    id_repo = user+'_'+repos
    print(id_repo)
    path = 'db/'+id_repo+'/'+V_CLASS+'/'

    try:
        # create output file if not exists
        os.makedirs(os.path.dirname(path))
    except OSError as e:
        print(e)

    print('Downloading...')
    c_url = g.get_user(user).get_repo(repos).clone_url
    repo = git.Repo.clone_from(c_url, 'repos/' + id_repo + '/', branch=br)
    commits = list(repo.iter_commits())
    print('Downloaded...')

    n = 0
    for c in tqdm(commits):

        message = c.message

        if V_CLASS == "misc":
            check = misc.search(message)
        elif V_CLASS == "injec":
            check = injec.search(message)
        elif V_CLASS == "csrf":
            check = csrf.search(message)
        elif V_CLASS == "dos":
            check = dos.search(message)
        elif V_CLASS == "auth":
            check = auth.search(message)
        elif V_CLASS == "ml":
            check = ml.search(message)
        elif V_CLASS == "pathtrav":
            check = pathtrav.search(message)
        elif V_CLASS == "xss":
            check = xss.search(message)
        elif V_CLASS == "sha1":
            check = sha1.search(message)

        parents = list(c.parents)

        if check is not None and len(parents) > 0 and commit_exists(conn, user, repos, str(c), str(V_CLASS)) == False:
            n += 1

            print(c)
            vpath = path + 'vuln'+ str(n) +'/'

            os.makedirs(os.path.dirname(vpath))
            repo.head.reference = c

            bpath = id_repo + '/'+ V_CLASS +'/'+ 'vuln'+str(n)+'/'

            archive_vuln(vpath + 'Vfix.tar', repo)

            send_blob(bpath + 'Vfix.tar', vpath + 'Vfix.tar', bucket)

            if len(parents) == 1:
                vulParent = parents[0]
            elif len(parents) > 1:
                vulParent = parents[1]

            diff = c.diff(vulParent, create_patch=True)
            if len(diff) == 0:
                vulParent = parents[0]
                diff = c.diff(vulParent, create_patch=True)

            repo.head.reference = vulParent

            archive_vuln(vpath + 'Vvul.tar', repo)
            send_blob(bpath + 'Vvul.tar', vpath + 'Vvul.tar', bucket)

            commit_url = g.get_user(user).get_repo(repos).get_commit(str(c)).html_url

            if commit_exists(conn, user, repos, str(c), V_CLASS) == False:
                add_commit(conn, n, user, repos, V_CLASS, str(c), vulParent, '', '', '', '', commit_url)
                conn.incr('stats:commit:n')
                conn.incr('stats:commit:%s:%s'%(user,repos))
                conn.incr('stats:commit:%s'%V_CLASS)

            add_blobs(diff,vpath)

            make_tarfile(vpath + 'Vdiff.tar', vpath + 'Vdiff')
            send_blob(bpath + 'Vdiff.tar', vpath + 'Vdiff.tar', bucket)
            shutil.rmtree(vpath + 'Vdiff')

    shutil.rmtree(path)
    return n

    # check arguments
if (len(sys.argv) != 2):
    print("Usage: python repos_miner.py <class>")
    sys.exit(0)

g = connect_to_github('config.json')
conn = connect_to_db('redis.json')
sgc = connect_to_gcloud_storage()
bucket = get_bucket(sgc, 'secbench1')

# get normal repositories
repos = get_repos_n(conn)

# datetime
datetime = time.strftime("%x") + ':' + time.strftime("%X")

# start measuring time
start = time.time()

# number of caught vulnerabilities
vuls = 0

# mine each repository
try:
    for r in repos[0]:
        repo_info = get_repos_info(conn,r)[0]
        owner = repo_info['owner']
        name = repo_info['name']
        branch = repo_info['branch']
        if class_mined(conn, owner, name, V_CLASS) == False:
            print('I\'m mining '+ owner +'/'+ name)
            vuls += mine_repos(owner, name, branch)
            set_class_mined(conn, owner, name, V_CLASS)
            add_repos_to_exp(conn, datetime, V_CLASS, owner, name)
        else:
            print(owner +'/'+ name+ ' already mined for '+ V_CLASS +' class')

        if os.path.exists('repos/'+ owner + '_' + name + '/'):
            remove_dir('repos/'+ owner + '_' + name)

    print('Process finished! Check results folder.')
    save_results(conn, start, datetime, vuls)
except KeyboardInterrupt:
    print('You have interrupted the process! Please wait, we are saving all the information.')
    save_results(conn, start, datetime, vuls)
