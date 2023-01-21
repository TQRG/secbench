# SECBENCH scripts

These are the scripts that were utilized to conduct the research.
To make use of these scripts with minimal modifications, you would need to have:
- github API key
- google cloud account
- redis cache


The information from the list above would need to be stored in configuration files, which are assumed to be in the same directory:
 - **config.json**: 
    ```{"github": {"username": "<USERNAME>","token": "<TOKEN>"}}```
 - **redis.json**:
     ```{"redis": {"host": "<HOST>","port": "<PORT>","password": "<PASSWORD>"}}```

If you plan to make use of these scripts, you will need to understand what purpose they serve.
 - **collect_repos.py**: Queries, creates and stores a local copy of a repository for analysis.
 - **repos_miner.py**: Processes the commits from each repository to identify vulnerabilities. Saves results in a data-store.

There are also these utility files which may need to be modified to work with your particular setup.
 - connect.py
 - db_op.py
 - utils.py

 - requirements.txt
