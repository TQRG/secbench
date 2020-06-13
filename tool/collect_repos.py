import csv
from github import BadCredentialsException
from github import Github
from github import GithubException
import sys
from tqdm import tqdm
import json
import operator
import redis
from db_op import *
from connect import *


def repos_has_more_than_one_commit(repo):
    c=0; res=False;
    #@TODO ISSUE: repo.get_commits().totalCount returns None (https://github.com/PyGithub/PyGithub/issues/415)
    for i in repo.get_commits():
        c+=1;
        if(c > 1):
            res = True;
            break;
    return res;



def get_repositories(mode):
    print('Collecting information from GitHub repositories...')
    global g, conn;

    # save information about repositories in the csv file
    i = 0;

    if mode == 'search':
        func = g.search_repositories(query=sys.argv[2])
    elif mode == 'all':
        func = g.get_repos(since=int(sys.argv[2]))

    # for each repository
    for repo in tqdm(func):
        status = 'n'
        print (repo.owner.login+'_'+repo.name)

        try:
            repo.get_contents('/')
        except GithubException as e:
            print(e)
            status = 'i' # has issues (blocked, empty...)

        if status != 'i':
            if repos_has_more_than_one_commit(repo) == False:
                print('Repository has less than two commits.')
                status='s' # too small

        if repo_exists(conn,repo.owner.login,repo.name,status) == False:
            create_repo(conn, repo, status)
            if status == 'n':
                create_lang(conn, repo, status)

        i += 1
        if i > int(sys.argv[3]):
            break

    print('\nProcess Finished! '+ sys.argv[3] + " repositories collected.")



# check arguments (@TODO: Check initPag and n_repos (int) and search_str (string))
if len(sys.argv) != 4:
    print('Usage: collect_repos.py all <initPag> <n_repos>')
    print('   or  collect_repos.py search <search_str> <n_repos>')
    sys.exit(0)

g = connect_to_github('config.json');
conn = connect_to_db('redis.json');
mode = sys.argv[1];
get_repositories(mode)
