from connect import *

def commit_exists(conn,user, repo, sha, v_class):
    return conn.exists('commit:%s:%s:%s:%s'%(user, repo, sha, v_class));

def add_commit(r, idf, user, repo, vclass, sha, shap, vuln, line, tool_res, obs, commit_url):
    pip = r.pipeline();
    pip.hmset('commit:%s:%s:%s:%s'%(user, repo, sha, vclass), {
            'id_f': idf,
            'repo_owner': user,
            'repo_name': repo,
            'class': vclass,
            'sha': sha,
            'sha-p': shap,
            'vuln?': vuln,
            'line': line, 'T':'', 'resT':tool_res, 'observations':obs, 'commit_url': commit_url, 'forked?':'', 'forked_from':''
            })
    res = pip.execute()
    return res;

def add_experiment(r, c_time, vclass, timeSpent, vuls):
    pip = r.pipeline();
    pip.hmset('exp:%s:%s:stats'%(c_time, vclass), {
            'time_spent': timeSpent,
            'n_vuls': vuls
            })
    pip.execute()

def class_mined(r, user, repo, vclass):
    pip = r.pipeline();
    pip.lrange('class:%s:%s'%(user, repo),0,-1)
    mclass = pip.execute()
    res = False;
    if vclass in mclass:
        res = True;

    return res;

def add_repo(pip, repo, status):
    if status != 'n':
        pip.hmset('repo:%s:%s:%s'%(repo.owner.login,repo.name,status), {
            'owner': repo.owner.login,
            'name': repo.name,
            'status': status
        })
    else:
        pip.hmset('repo:%s:%s:%s'%(repo.owner.login,repo.name,status), {
            'owner': repo.owner.login,
            'name': repo.name,
            'mined': '',
            'status': status,
            'branch': repo.default_branch,
            'languages': repo.get_languages()
        })
    return id;

def lang_exists(conn,repo_owner, repo_name):
    return conn.exists('lang:%s:%s'%(repo_owner,repo_name))

def add_lang(pip, repo, status):
    lang = repo.get_languages()
    dlang = {};
    for key, value in lang.iteritems():
        dlang[key] = value
        pip.sadd('lang:%s'%key,'repo:%s:%s:%s'%(repo.owner.login,repo.name,status));
    if len(dlang) != 0:
        pip.hmset('lang:%s:%s'%(repo.owner.login,repo.name), dlang)

def create_lang(conn,repo, status):
    pip = conn.pipeline(True)
    if lang_exists(conn,repo.owner.login,repo.name) == False:
        conn.incr('stats:lang')
        add_lang(pip, repo, status);
    pip.execute();

def get_repos_n(conn):
    pip = conn.pipeline(True)
    pip.keys(pattern='repo:*:*:n')
    res = pip.execute()
    return res;

def class_mined(conn, repo_owner, repo_name, v_class):
    m_class = conn.lrange('class:%s:%s'%(repo_owner, repo_name),0,-1)
    res = False;
    if v_class in m_class:
        res = True;
    return res;

def add_experiment(conn, c_time, v_class, timeSpent, vuls):
    conn.hmset('exp:%s:%s:stats'%(c_time, v_class), {
            'time_spent': timeSpent,
            'n_vuls': vuls
            })

def get_repo_status(conn,repo_owner, repo_name,status):
    return conn.hget('repo:%s:%s:%s'%(repo_owner,repo_name,status),'status')

def get_repos_info(conn,repo):
    pip = conn.pipeline(True)
    pip.hgetall(repo);
    res = pip.execute()
    return res;

def repo_exists(conn,repo_owner, repo_name, status):
    return conn.exists('repo:%s:%s:%s'%(repo_owner,repo_name, status))

def set_class_mined(conn, owner, name, v_class):
    pip = conn.pipeline(True)
    pip.lpush('class:%s:%s'%(owner, name), v_class)
    pip.execute()

def add_repos_to_exp(conn, datetime, v_class, owner, name):
    pip = conn.pipeline(True)
    pip.sadd('exp:%s:%s:repos'%(datetime, v_class),'repo:%s:%s:n'%(owner, name));
    pip.execute()

def create_repo(conn,repo,status):
        pip = conn.pipeline(True)
        conn.incr('stats:repo:%s'%status)
        add_repo(pip, repo, status)
        pip.execute();
