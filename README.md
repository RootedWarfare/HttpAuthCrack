HttpAuthCrack
=============

Http Basic Auth Bruteforcer


Description:

From a list of IPs, check the basic auth with the credentials given or using admin/admin by default.
To create the list of IPs, you can use a Shodan query or a file with an IP per line
Note that shodan API only give 100 results per query instead of the real number of results found.

Output:
  An html file with a list of IPs with access granted and the credentials working for these IPs

Dependencies:
  Shodan library: easy_install shodan

Usage example:
  httpauthcrack.py -u user -p pass -s "linksys port:80" -v

Author:
 Ignacio Sorribas (a.k.a. H4rds3c)         sorribas[at]gmail.com / hardsec[at]gmail.com
 http://hardsec.net

Versions:

v0.1 (2013/08/08).
  - First release.

v0.2 (2014/02/04).
  - Added port 8080 from shodan results to list of IPs.
  - Fix a bug in the arguments command line
  - Added option -d / --port to look for into shodan results
  - Optimised to avoid create all threads specified by -t switch if they aren't needed

v0.3 (2014/02/09).
  - Filter of false positives on many IP phone devices.
  - Optimized code from "check_basic_auth" function.

v0.4 (2014/02/27).
  - Fix bugs in "test_host" function
  - Separate log functions in other file
  - Add colors to output
  - Add report dir with templates for header.html and footer.html to make the reports.
  - the output report is stored in the output folder
  - Embeded Logo added to the html report
