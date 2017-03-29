# Repository Miner

This tool searches for commits related to vulnerabilities in repositories collected by the [repos collector](https://github.com/SofiaReis/search-vulnerabilities-from-repositories/tree/master/repos-collector) which is a python script that searches the existence of vulnerabilities by analyzing the commits messages. The output is a file for each repository stored in the input file. Each output file has a list of all the detected commits (url commit, message commit).

Available for GitHub.
  
# Repos Collector

This python script collects informations about repositories from several source code hosting websites (e.g., github, bitbucket, sourceforge, svn, etc). The output file saves the repository owner and the repository name.

Available for GitHub.

# Configuration

For each tool (Repository Miner and Repos Collector), you need to configure the run environment. Follow the steps below:

* Check **requirements.txt** to see the necessary packages to run the script.

* Modify the config.json file for authentication on GitHub API and to get a higher rate (requests per hour). See [Rates Documentation](https://developer.github.com/v3/#rate-limiting). Example of the config.json file, below:
  ```json
      {
        "github": 
        {
           "username": "your_username",
           "token": "personal_access_token"
        }
      }
  ```

