# Secbench Dataset & Mining Tool

Secbench is a database of security vulnerabilities fixes mined from Github. We mined 238 projects - accounting to more than 1M commits - for 16 different vulnerabilities [patterns](https://tqrg.github.io/secbench/patterns.html). Meanwhile (in 2020), the dataset was updated. The database integrates 676 real security vulnerabilities from 114 different projects. 

Our main goal with this approach is the identification and extraction of real security vulnerabilities patched by developers. We started with the identification of several security patterns to use on our [mining tool](https://github.com/TQRG/secbench-mining-tool). To understand what would be the most popular patterns on Github, we based ourselves on Github searches and Top 10 OSWAP 2017. Thereafter, we kept adding more patterns and we still have place for many more. The patterns were used for mining commits' messages. As we can see on the figure below, after saving the data there is an evaluation process to validate whether the caught sample is really the fix of a security vulnerability or not. If approved, the sample's information is updated on the database and, consequently, the test case is added to the final database. After the 2020 update, the patterns used to mine vulnerabilities were converted to the CWE classification system. Score and severity were added to the vulnerabilities classified with a CVE code. Each entry has the information to the fix (sha) and vulnerable code (sha-p).

**Research:** If you use the datase, cite it.
We are working on a new version of the dataset.

### Versions

2020 v. [Dataset](https://github.com/TQRG/secbench/blob/master/dataset/secbench.csv)

# Publications

**If you use the dataset in your research, please cite one of the publications below:**

"A Database of Existing Vulnerabilities to Enable Controlled Testing Studies" Sofia Reis & Rui Abreu, International Journal of Secure Software Engineering (IJSSE) 2017 [[Paper]](https://www.igi-global.com/article/a-database-of-existing-vulnerabilities-to-enable-controlled-testing-studies/201213)

"SECBENCH: A Database of Real Security Vulnerabilities" Sofia Reis & Rui Abreu, SECSE 2017, Oslo, Norway [[Paper]](http://ceur-ws.org/Vol-1977/paper6.pdf)

"Using Github to Create a Dataset of Natural Occuring Vulnerabilities" Sofia Reis & Rui Abreu, DX 2017, Brescia, Italy [[Poster]](https://github.com/TQRG/secbench/raw/master/papers/dx17/poster.pdf) and [[Patterns]](https://github.com/TQRG/secbench/raw/master/papers/dx17/patterns.pdf)


# License
MIT License, see [license.txt](https://github.com/TQRG/secbench/blob/master/license.txt) for more information.
