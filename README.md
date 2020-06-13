# Secbench Dataset & Mining Tool

_Soon_: SecBench++

Secbench is a database of real security vulnerabilities mined from Github. We mined 238 projects - accounting to more than 1M commits - for 16 different vulnerability [patterns](https://tqrg.github.io/secbench/patterns.html), yielding a database with 602 real security vulnerabilities. 

Our main goal with this approach is the identification and extraction of real security vulnerabilities fixed/patched by real developers. We started with the identification of several security patterns to use on our [mining tool](https://github.com/TQRG/secbench-mining-tool). To understand what would be the most popular patterns on Github, we based ourselves on Github searches and Top 10 OSWAP 2017. Thereafter, we kept adding more patterns and we still have place for many more. The patterns were used for mining commits' messages. As we can see on the figure below, after saving the data there is an evaluation process to validate whether the caught sample is really the fix of a security vulnerability or not. If approved, the sample's information is updated on the database and, consequently, the test case is added to the final database.


### Test Cases Structure

Every time a pattern is found in a commit by the mining tool, a test case is created. The test case has 3 folders: Vfix with the non-vulnerable source code from the commit where the pattern was caught (child), Vvul with the vulnerable source code from the previous commit (parent) which we consider the real vulnerability; and, Vdiff with two folders, added and deleted, where the added lines to fix the vulnerability and the deleted lines that represent the security vulnerability are stored (as we can see in the figure below).

### Versions

[v.1.0](https://console.cloud.google.com/storage/browser/v0_0_1/?project=secbench-161618)
* 602 security vulnerabilities
* 16 Patterns: TOP 10 OSWAP 2017, Memory Leak, Overflow, Resourse Leaks, Denial-of-Service, Path Traversal, Miscellaneous
* 13 languages: Ruby, Java, Scala, Php, C, Objc, Objc++, Python, Swift, Groovy, C++, JavaScript, and others (which includes xml).

| Patterns (OSWAP) | injec | auth | xss | bac | smis | sde | iap | csrf | ucwkv | upapi | Total |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | 
| #vulns | 97 | 44 | 141 | 2 | 9 | 17 | 14 | 33 | 22 | 2 | 381 |

| Patterns (Others) | ml | over | dos | pathtrav | rl | misc | Total |
| --- | --- | --- | --- | --- | --- | --- | --- |
| #vulns | 77 | 15 | 38 | 15 | 4 | 72 | 221 |


# Publications

"SECBENCH: A Database of Real Security Vulnerabilities" Sofia Reis & Rui Abreu, SECSE 2017, Oslo, Norway [[Paper]](http://ceur-ws.org/Vol-1977/paper6.pdf)

"Using Github to Create a Dataset of Natural Occuring Vulnerabilities" Sofia Reis & Rui Abreu, DX 2017, Brescia, Italy [[Poster]](https://github.com/TQRG/secbench/raw/master/papers/dx17/poster.pdf) and [[Patterns]](https://github.com/TQRG/secbench/raw/master/papers/dx17/patterns.pdf)


# License
MIT License, see [license.txt](https://github.com/TQRG/secbench/blob/master/license.txt) for more information.
