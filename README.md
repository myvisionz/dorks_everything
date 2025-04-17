

# google dorks

## pages


### subdomain

```
site:*.example.com
```

```
site:*.*.example.com
```


### Form pages

```
site:example.com intitle:"Submit Feedback" | intitle:"Contact us" | intitle:"Join Our Waitlist" | intitle:"Subscribe" | intitle:"Newsletter" | intitle:"Unsubscribe" | intitle:"Email Support" | intitle:"Customer Support"
```

### Login Pages

```
inurl:login | inurl:signin | intitle:login | intitle:"sign in" | inurl:secure | inurl:auth | inurl:/register | inurl:portal site:example[.]com
```




### INDEX

```
site:example.com intext:"index of" | "parent directory" | intitle:index.of
```

```
site:example.com intitle:"Index of" wp-admin
```

```
site:example.com intext:"Index of /" +.htaccess
```


## files

### robots & sitemap

```
site:example.com ext:txt | ext:xml | inurl:robots | inurl:sitemap | intext:robots | intext:sitemap 
```

### Publicly Exposed Documents

```
site:example.com ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv | ext:xls | ext:xlsx | ext:txt
```



## footprint

### EMAIL
```
site:example.com (filetype:doc OR filetype:xlsx) intext:@gmail.com
```

### Code Leaks

```
site:pastebin.com | site:paste2.org | site:pastehtml.com | site:slexy.org | site:snipplr.com | site:snipt.net | site:textsnip.com | site:bitpaste.app | site:justpaste.it | site:heypasteit.com | site:hastebin.com | site:dpaste.org | site:dpaste.com | site:codepad.org | site:jsitor.com | site:codepen.io | site:jsfiddle.net | site:dotnetfiddle.net | site:phpfiddle.org | site:ide.geeksforgeeks.org | site:repl.it | site:ideone.com | site:paste.debian.net | site:paste.org | site:paste.org.ru | site:codebeautify.org  | site:codeshare.io | site:trello.com 'example.com'
```

### Cloud Storage

```
site:s3.amazonaws.com "example.com"
```

```
site:blob.core.windows.net "example.com"
```

```
site:googleapis.com "example.com"
```

```
site:drive.google.com "example.com"
```

```
site:dev.azure.com "example[.]com"
```

```
site:onedrive.live.com "example[.]com"
```

```
site:digitaloceanspaces.com "example[.]com"
```

```
site:sharepoint.com "example[.]com"
```

```
site:s3-external-1.amazonaws.com "example[.]com"
```

```
site:s3.dualstack.us-east-1.amazonaws.com "example[.]com"
```

```
site:dropbox.com/s "example[.]com"
```

```
site:box.com/s "example[.]com"
```

```
site:docs.google.com inurl:"/d/" "example[.]com"
```










### git

```
site:example.com "index of /.git" | intext:"index of /.git" "parent directory"
```

```
site:example.com inurl:.git-credentials
```

```
site:example.com inurl:.gitconfig
```

```
site:example.com intext:"index of /.git" "parent directory"
```

```
site:example.com filetype:git -github.com inurl:"/.git"
```

```
site:example.com (intext:"index of /.git") ("parent directory")
```

```
site:example.com inurl:ORIG_HEAD
```

```
site:example.com intitle:"index of" ".gitignore"
```

```
site:example.com ".git" intitle:"Index of"
```

```
site:example.com (intext:"index of /.git") ("parent directory")
```

```
site:example.com "Parent Directory" "Last modified" git
```

```
site:example.com inurl:git
```

### log

```
site:example.com intitle:index.of intext:log
```

```
site:example.com filetype:log "See `ipsec --copyright"
```

```
site:example.com filetype:log access.log -CVS
```

```
site:example.com filetype:log cron.log
```

```
site:example.com filetype:log intext:"ConnectionManager2"
```

```
site:example.com filetype:log inurl:"password.log"
```

```
site:example.com filetype:log inurl:password.log
```

```
site:example.com intitle:index.of cleanup.log
```

```
site:example.com intitle:index.of filetype:log
```

```
site:example.com intitle:index.of log
```

```
site:example.com filetype:log inurl:nginx
```

```
site:example.com filetype:log inurl:database
```

```
site:example.com filetype:log inurl:bin
```

```
site:example.com filetype:syslog
```

```
site:example.com allintext:username filetype:log
```

```
site:example.com inurl:error filetype:log
```

```
site:example.com inurl:nginx filetype:log
```





# github dorks

### Search in Github Gist

```
https://gist.github.com/search?q=*.'example.com'
```

### Find Github password

```
https://github.com/search?q=%22example.com%22+password&type=Code
```

### Find Github npmrc _auth

```
https://github.com/search?q=%22example.com%22+npmrc%20_auth&type=Code
```

### Find Github dockercfg

```
https://github.com/search?q=%22example.com%22+dockercfg&type=Code
```

### Find Github pem private

```
https://github.com/search?q=%22example.com%22+pem%20private&type=Code
```

### Find Github id_rsa

```
https://github.com/search?q=%22example.com%22+id_rsa&type=Code
```

### Find Github aws_access_key _id

```
https://github.com/search?q=%22example.com%22+aws_access_key_id&type=Code
```

### Find Github s3cfg

```
https://github.com/search?q=%22example.com%22+s3cfg&type=Code
```

### Find Github htpasswd

```
https://github.com/search?q=%22example.com%22+htpasswd&type=Code
```

### Find Github git-credentials

```
https://github.com/search?q=%22example.com%22+git-credentials&type=Code
```

### Find Github bashrc password

```
https://github.com/search?q=%22example.com%22+bashrc%20password&type=Code
```

### Find Github sshd_config

```
https://github.com/search?q=%22example.com%22+sshd_config&type=Code
```

### Find Github xoxp OR xoxb OR xoxa

```
https://github.com/search?q=%22example.com%22+xoxp%20OR%20xoxb%20OR%20xoxa&type=Code
```

### Find Github SECRET_KEY

```
https://github.com/search?q=%22example.com%22+SECRET_KEY&type=Code
```

### Find Github client_secret

```
https://github.com/search?q=%22example.com%22+client_secret&type=Code
```

### Find Github github_token

```
https://github.com/search?q=%22example.com%22+github_token&type=Code
```

### Find Github api_key

```
https://github.com/search?q=%22example.com%22+api_key&type=Code
```

### Find Github FTP

```
https://github.com/search?q=%22example.com%22+FTP&type=Code
```

### Find Github app_secret

```
https://github.com/search?q=%22example.com%22+app_secret&type=Code
```

### Find Github s3.yml

```
https://github.com/search?q=%22example.com%22+.env&type=Code
```

### Find Github .exs

```
https://github.com/search?q=%22example.com%22+.exs&type=Code
```

### Find Github beanstalkd.yml

```
https://github.com/search?q=%22example.com%22+beanstalkd.yml&type=Code
```

### Find Github deploy.rake

```
https://github.com/search?q=%22example.com%22+deploy.rake&type=Code
```

### Find Github mysql

```
https://github.com/search?q=%22example.com%22+mysql&type=Code
```

### Find Github credentials

```
https://github.com/search?q=%22example.com%22+credentials&type=Code
```

### Find Github PWD

```
https://github.com/search?q=%22example.com%22+PWD&type=Code
```

### Find Github .bash_history

```
https://github.com/search?q=%22example.com%22+.bash_history&type=Code
```

### Find Github .sls

```
https://github.com/search?q=%22example.com%22+.sls&type=Code
```

### Find Github secrets

```
https://github.com/search?q=%22example.com%22+secrets&type=Code
```

### Find Github composer.json

```
https://github.com/search?q=%22example.com%22+composer.json&type=Code
```




# shodan dorks




# others

### Cloud Storage and Buckets

```
https://cse.google.com/cse?cx=002972716746423218710:veac6ui3rio#gsc.tab=0&gsc.q=example.com
```



### Certificate Transparency #1

```
https://crt.sh/?q=example.com
```

### Certificate Transparency #2 📒：在crt.sh的规则中，%25代表通配符

```
https://crt.sh/?q=%25.example.com
```

### What CMS?

```
https://whatcms.org/?s=example.com
```

### SSL Server Test

```
https://www.ssllabs.com/ssltest/analyze.html?d=example.com
```

### Search in Wayback Machine #1

```
https://web.archive.org/web/*/example.com/*
```

### Search in Wayback Machine #2 📒：在Wayback Machine的规则中，*代表通配符

```
https://web.archive.org/web/*/*.example.com/*
```

### Search in Shodan

```
https://www.shodan.io/search?query=example.com
```

### Search in grep.app

```
https://grep.app/search?q=example.com
```

### Check Security Headers

```
https://securityheaders.com/?q=example.com&followRedirects=on
```




### Search in OpenBugBounty

```
https://www.openbugbounty.org/search/?search=example.com
```

### Search in Censys Hosts

```
https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=100&virtual_hosts=EXCLUDE&q=example.com
```

### Search in Censys Certificates

```
https://search.censys.io/certificates?q=example.com
```

### Reverse ip lookup

```
https://viewdns.info/reverseip/?host=example.com&t=1
```

### Search in bgp ASN

```
https://bgp.he.net/search?search%5Bsearch%5D=example.com&commit=Search
```

### Search in httpstatus

```
https://httpstatus.io
```

### Search in asnlookup ASN

```
https://asnlookup.com/organization/example.com
```

### Search in DomainEye

```
https://domaineye.com/similar/example.com
```

### Test CrossDomain

```
https://example.com/crossdomain.xml
```

### Search in Rapiddns Subdomain

```
https://rapiddns.io/subdomain/example.com?full=1#result
```

### Search in Virustotal Subdomain

```
https://www.virustotal.com/gui/domain/example.com/relations
```




### DNSBin - The request.bin of DNS!

```
https://requestbin.net/
```

### WordPress Scan #1

```
https://hackertarget.com/wordpress-security-scan/
```

### WordPress Scan #2

```
https://wprecon.com/
```

### Facebook Certificate Transparency Monitoring (Recon)

```
https://developers.facebook.com/tools/ct/
```

### IP converter

```
https://www.smartconversion.com/unit_conversion/IP_Address_Converter.aspx
```

### Domain History Checker

```
https://whoisrequest.com/history/
```

### Source code search engine

```
https://publicwww.com/
```



# 待整理，全部是google dorks

### Open Redirect

```
site:example.com inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http
```

### Password files

```
site:example.com 'password' filetype:doc | filetype:pdf | filetype:docx | filetype:xls | filetype:dat | filetype:log
```

### Database related

```
site:example.com intext:'sql syntax near' | intext:'syntax error has occurred' | intext:'incorrect syntax near' | intext:'unexpected end of SQL command' | intext:'Warning: mysql_connect()' | intext:'Warning: mysql_query() | intext:'Warning: pg_connect()' | filetype:sql | ext:sql | ext:dbf | ext:mdb
```

### Config and log files

```
site:example.com ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini | ext:log
```

### Backup and old files

```
site:example.com ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup
```

### phpinfo()

```
site:example.com ext:php intitle:phpinfo 'published by the PHP Group'
```

### S3 Bucket

```
site:amazonaws.com 'example.com'
```

### Search in github/gitlab/StackOverflow

```
site:github.com | site:gitlab.com | site:stackoverflow.com 'example.com'
```

### WordPress

```
site:example.com inurl:wp- | inurl:wp-content | inurl:wp-admin | inurl:wp-includes | inurl:plugins | inurl:uploads | inurl:themes | inurl:download
```

### Search in 3rd Party Vendors

```
site:scribd.com | site:npmjs.com | site:npm.runkit.com | site:libraries.io | site:coggle.it | site:papaly.com | site:prezi.com | site:jsdelivr.net | site:gitter.im 'example.com'
```

### SQL errors

```
site:example.com intext:'sql syntax near' | intext:'syntax error has occurred' | intext:'incorrect syntax near' | intext:'unexpected end of SQL command' | intext:'Warning: mysql_connect()' | intext:'Warning: mysql_query()' | intext:'Warning: pg_connect()'
```

### PHP errors / warning

```
site:example.com 'PHP Parse error' | 'PHP Warning' | 'PHP Error'
```

### Important Dorks

```
site:example.com filetype:txt | inurl:.php.txt | ext:txt
```

### Error Log Source Code

```
'index of' error_log intext:example.com
```

### Shodan Api

```
inurl:pastebin 'SHODAN_API_KEY'
```

### Linkedin Employees

```
site:linkedin.com employees
```

### Search in Subdomainfinder Subdomain

```
site:subdomainfinder.c99.nl inurl:example.com
```

### Apache Config Files

```
site:example.com filetype:config 'apache'
```

### Apache Struts RCE

```
site:example.com ext:action | ext:struts | ext:do
```

### Search in Bitbucket and Atlassian

```
site:bitbucket.org | site:atlassian.net 'example.com'
```

### .git folder

```
inurl:'/.git 'example.com -github
```

### Digital Ocean Spaces

```
site:digitaloceanspaces.com 'example.com'
```

### IIS Windows Server

```
intitle:'IIS Windows Server' 'example.com'
```

### Find HTML Files

```
intext:'index of' '.html' inurl:example.com
```

### Find Repository

```
intext:'index of' 'repository' inurl:example.com
```



# 待整理，都有




### Finding Backdoors

```
inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini
```

### Install / Setup files

```
inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config
```

### .htaccess sensitive files

```
inurl:"/phpinfo.php" | inurl:".htaccess" | inurl:"/.git"  -github
```

### Search in GITHUB

```
https://github.com/search?q=*.example.com
```

### Check in ThreatCrowd

```
http://threatcrowd.org/domain.php?domain=example.com
```

### Find SWF

```
+inurl: +ext:swf
```

### Find MIME-SWF

```
site: mime:swf
```

### Find SWF links in the past

```
https://web.archive.org/cdx/search?url=example.com/&matchType=domain&collapse=urlkey&output=text&fl=original&filter=urlkey:.*swf&limit=100000&_=1507209148310
```

### Find MIME-SWF links in the past

```
https://web.archive.org/cdx/search?url=example.com/&matchType=domain&collapse=urlkey&output=text&fl=original&filter=mimetype:application/x-shockwave-flash&limit=100000&_=1507209148310
```

### Search in Reddit

```
https://www.reddit.com/search/?q=example.com&source=recent
```

### Search WP Config Backup

```
http://wwwb-dedup.us.archive.org:8083/cdx/search?url=example.com/&matchType=domain&collapse=digest&output=text&fl=original,timestamp&filter=urlkey:.*wp[-].*&limit=1000000&xx=
```

### Search in Censys (IPv4)

```
https://censys.io/ipv4?q=example.com
```

### Search in Censys (Domain)

```
https://censys.io/domain?q=example.com
```

### Vulnerable Servers

```
inurl:"/geoserver/ows?service=wfs"
```

### ArcGIS REST Services Directory

```
intext:"ArcGIS REST Services Directory" intitle:"Folder: /"
```

### wp-content Juicy Info

```
inurl:/wp-content/uploads/wpo_wcpdf
```

### main.yml file

```
intitle:"index of "main.yml""
```

### Admin Portal

```
inurl:/admin.aspx
```

### Wordpress Juicy file 1

```
inurl:/wp-content/uploads/wpo_wcpdf
```

### File Upload

```
inurl:uploadimage.php
```

### Vulnerable Wordpress Plugin

```
inurl:*/wp-content/plugins/contact-form-7/
```

### Sensitive File

```
intitle:index.of conf.php
```

### Sharing API Info

```
intitle:"Sharing API Info"
```

### Sensitive Admin Backup

```
intitle:"Index of" inurl:/backup/ "admin.zip"
```

### Github API

```
intitle:"index of" github-api
```

### Wordpress Juicy file 2

```
inurl:wp-content/uploads/wcpa_uploads
```

### Drupal Login

```
inurl:user intitle:"Drupal" intext:"Log in" -"powered by"
```

### Joomla Database/

```
inurl: /libraries/joomla/database/
```

### Sql File

```
inurl:"php?sql=select" ext:php
```

### Wordpress Juicy file 3

```
inurl:"wp-content" intitle:"index.of" intext:wp-config.php
```

### Remote procedure call protocol

```
intext:"index of" inurl:json-rpc
```

### Sensitive File

```
intitle:"index of" "download.php?file="
```

### jwks-rsa file

```
intext:"index of" inurl:jwks-rsa
```

### Wordpress Backup

```
inurl:"wp-content" intitle:"index.of" intext:backup"
```

### Mysql file

```
intitle:index.of conf.mysql
```

### Sensitive File

```
intitle:"index of" "users.yml" | "admin.yml" | "config.yml"
```

### Docker-Compose yml file

```
intitle:"index of" "docker-compose.yml"
```

### Sensitive File

```
intext:pom.xml intitle:"index of /"
```

### Sensitive File

```
intext:"Index of" intext:"/etc"
```

### Directories containing SQL Installs and/or SQL databases

```
"sql" "parent" intitle:index.of -injection
```





# pentesting google dorrks webpage

### ASPX/ASP/JSP/JSPX EXTENSION WITH PARAMETERS
```
site:example.com inurl:? ext:aspx | ext:asp | ext:jsp | ext:jspx
```
### PORTS
```
site:example.com inurl:"8443/login.jsp"
```

```
site:example.com:8888
```

### PEOPLESOFT
```
site:example.com intitle:"Oracle+PeopleSoft+Sign-in"
```

### IIS
```
site:example.com intitle:"IIS Windows Server"
```

### PHPMYADMIN
```
site:example.com inurl:"setup/index.php" | inurl:"phpmyadmin" | inurl:"phpMyAdmin" | inurl:"admin/phpMyAdmin" | inurl:"pma/setup/index.php" | intitle:"index of /phpMyAdmin" | "Index of" inurl:phpmyadmin | inurl:"phpMyAdmin/setup/index.php" | intitle:"phpMyAdmin setup"
```

### GEOSERVER
```
site:example.com inurl:/geoserver/web/
```

### GRAFANA
```
site:example.com intitle:"Grafana"
```

```
site:example.com intitle:"grafana" inurl:"/grafana/login" "Forgot your password"
```

```
site:example.com intitle:"Grafana - Home" inurl:/orgid
```

```
site:example.com intitle:Grafana inurl:orgid
```

```
site:example.com inurl:login "Welcome to Grafana"
```

```
site:example.com "Welcome to Grafana" inurl:/orgid
```

```
site:example.com intitle:"Welcome to Grafana"
```

### PHPLDAPADMIN
```
site:example.com intitle:"phpLDAPadmin"
```

```
site:example.com intitle:"phpLDAPadmin" inurl:cmd.php
```

### JENKINS
```
site:example.com intitle:"Dashboard [Jenkins]"
```

```
site:example.com intitle:"Sign in [Jenkins]" inurl:"login?from"
```

### WERKZEUG
```
site:example.com intitle:"Werkzeug"
```

### SYMFONY
```
site:example.com intitle:"Symfony"
```

### WEBFLOW
```
site:example.com intext:"The page you are looking for doesn't exist or has been moved."
```

### JOOMLA
```
site:example.com intext:"Joomla! - Open Source Content Management"
```

```
site:example.com site:*/joomla/administrator
```

### WORDPRESS
```
site:example.com intext:"index of" "wp-content.zip"
```

```
site:example.com inurl:wp-content | inurl:wp-includes
```

```
site:example.com intitle:"Index of" wp-admin
```

### ADMIN.ZIP
```
site:example.com intitle:"index of /" "admin.zip" "admin/"
```

### ADMIN.ZIP
```
site:example.com intext:"Index of" intext:"/etc"
```

### BACKUP
```
site:example.com intext:"Index of" intext:"backup.tar"
```

```
site:example.com inurl:backup | inurl:backup.zip | inurl:backup.rar | inurl:backup.sql | inurl:backup filetype:sql | inurl:save filetype:sql | inurl:web.zip | inurl:website.zip | filetype:bak | filetype:abk | inurl:backup "Parent Directory"
```

### BACKEND
```
site:example.com intext:"Index of" intext:"backend/"
```

### SOURCE-CODE
```
site:example.com Index of" intext:"source_code.zip | Index of" intext:"zip
```

### DOCKER-COMPOSE
```
site:example.com intitle:"index of" "docker-compose.yml"
```

### ATLASSIAN
```
site:example.com inurl:Dashboard.jspa intext:"Atlassian Jira Project Management Software"
```

### OPENBUGBOUNTY REPORTS
```
site:openbugbounty.org inurl:reports intext:"example.com"
```

### JUICY EXTENSIONS
```
site:example.com ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess
```

### SENSITIVE INFORMATION
```
site:example.com ext:doc | ext:docx intext:"internal use only | confidential"
```

```
site:example.com ext:pdf intext:"internal use only | confidential"
```

```
site:s3.amazonaws.com confidential OR "top secret" "example.com"
```

```
site:blob.core.windows.net | site:googleapis.com | site:drive.google.com | site:docs.google.com/spreadsheets | site:groups.google.com "example.com"
```

```
site:example.com allintext:username filetype:log
```

```
site:example.com inurl:/proc/self/cwd
```

```
site:example.com intitle:"index of" inurl:ftp
```

```
site:example.com intitle:"Apache2 Ubuntu Default Page: It works"
```

```
site:example.com inurl:"server-status" intitle:"Apache Status" intext:"Apache Server Status for"
```

```
site:example.com inurl:"/sym404/" | inurl:"/wp-includes/sym404/"
```

```
site:example.com inurl:"/app_dev.php"
```

```
site:example.com inurl:/webmail/ intext:Powered by IceWarp Server
```

```
site:example.com ext:env "db_password"
```

```
site:example.com inurl:"/printenv" "REMOTE_ADDR"
```

```
site:example.com intitle:"index of" "users.yml" | "admin.yml" | "config.yml"
```

```
site:example.com intitle:"index of" "docker-compose.yml"
```

```
site:example.com Index of" intext:"source_code.zip | Index of" intext:"zip
```

```
site:example.com intext:"Index of" intext:"backend/" | intext:"backup.tar" | intitle:"index of db.sqlite3" | intext:"/etc" | intext:"bitbucket-pipelines.yml" | intext:"database.sql" | "config/db" | "styleci.yml" ".env" | inurl:"/sap/bc/gui/sap/its/webgui?sap-client=SAP*" | intitle:"index of /" "admin.zip" "admin/" | intitle:"index of " "shell.txt" | intitle:"index of " "application.yml" | intext:"index of" "wp-content.zip" | intext:"index of" smb.conf | intitle:"index of" /etc/shadow
```

### MY CUSTOM DORK
```
site:example.com intext:"Index of" intext:"database.sql"
```

```
site:example.com intext:"Index of" intext:"admin.tar.gz"
```

### AEM
```
site:example.com inurl:"/content/dam"
```

### PHPINFO
```
site:example.com inurl:"phpinfo.php"
```

```
site:example.com intitle:phpinfo "published by the PHP Group"
```

```
site:example.com inurl:info.php intext:"PHP Version" intitle:"phpinfo()"
```

### SQL ERROR
```
site:example.com intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"
```

### PHP ERROR
```
site:example.com "PHP Parse error" | "PHP Warning" | "PHP Error"
```

### DATABASE
```
site:example.com inurl:db.sql | inurl:db.sqlite | inurl:setup.sql | inurl:mysql.sql | inurl:users.sql | inurl:backup.sql | inurl:db filetype:sql | inurl:backup filetype:sql | inurl:backup filetype:sql | inurl:/db/websql/
```

```
site:example.com create table  filetype:sql
```

```
site:example.com "-- MySQL dump" "Server version" "Table structure for table"
```

```
site:example.com filetype:sql
```

### AWS S3
```
site:http://s3.amazonaws.com intitle:index.of.bucket "example.com"
```

```
site:http://amazonaws.com inurl:".s3.amazonaws.com/" "example.com"
```

```
site:.s3.amazonaws.com "Company" "example.com"
```

```
intitle:index.of.bucket "example.com"
```

```
site:http://s3.amazonaws.com intitle:Bucket loading "example.com"
```

```
site:*.amazonaws.com inurl:index.html "example.com"
```

```
Bucket Date Modified "example.com"
```

### KIBANA
```
site:example.com inurl:"/app/kibana#"
```

### XSS PARAMETERS
```
site:example.com inurl:q= | inurl:s= | inurl:search= | inurl:query= | inurl:keyword= | inurl:lang= inurl:&
```

### OPEN REDIRECT PARAMETERS
```
site:example.com inurl:url= | inurl:return= | inurl:next= | inurl:redirect= | inurl:redir= | inurl:ret= | inurl:r2= | inurl:page= inurl:& inurl:http
```

```
site:example.com inurl:(url= | return= | next= | redirect= | redir= | ret= | r2= | page=) inurl:& inurl:http
```

### SQLI PARAMETERS
```
site:example.com inurl:id= | inurl:pid= | inurl:category= | inurl:cat= | inurl:action= | inurl:sid= | inurl:dir= inurl:&
```

### SSRF PARAMETERS
```
site:example.com inurl:include | inurl:dir | inurl:detail= | inurl:file= | inurl:folder= | inurl:inc= | inurl:locate= | inurl:doc= | inurl:conf= inurl:&
```

### RCE PARAMETERS
```
site:example.com inurl:cmd | inurl:exec= | inurl:query= | inurl:code= | inurl:do= | inurl:run= | inurl:read= | inurl:ping= inurl:&
```

# main

### PHP extension w/ parameters

```
site:example.com ext:php inurl:?
```

### API Endpoints

```
site:example[.]com inurl:api | site:*/rest | site:*/v1 | site:*/v2 | site:*/v3
```

### High % inurl keywords

```
inurl:conf | inurl:env | inurl:cgi | inurl:bin | inurl:etc | inurl:root | inurl:sql | inurl:backup | inurl:admin | inurl:php site:example[.]com
```

### Server Errors

```
inurl:"error" | intitle:"exception" | intitle:"failure" | intitle:"server at" | inurl:exception | "database error" | "SQL syntax" | "undefined index" | "unhandled exception" | "stack trace" site:example[.]com
```

### XSS prone parameters

```
inurl:q= | inurl:s= | inurl:search= | inurl:query= | inurl:keyword= | inurl:lang= inurl:& site:example.com
```

### SQLi Prone Parameters

```
inurl:id= | inurl:pid= | inurl:category= | inurl:cat= | inurl:action= | inurl:sid= | inurl:dir= inurl:& site:example.com
```

### SSRF Prone Parameters

```
inurl:http | inurl:url= | inurl:path= | inurl:dest= | inurl:html= | inurl:data= | inurl:domain=  | inurl:page= inurl:& site:example.com
```

### LFI Prone Parameters

```
inurl:include | inurl:dir | inurl:detail= | inurl:file= | inurl:folder= | inurl:inc= | inurl:locate= | inurl:doc= | inurl:conf= inurl:& site:example.com
```

### RCE Prone Parameters

```
inurl:cmd | inurl:exec= | inurl:query= | inurl:code= | inurl:do= | inurl:run= | inurl:read=  | inurl:ping= inurl:& site:example.com
```

### File upload endpoints

```
site:example.com ”choose file”
```

### SWAGGER-UI

```
site:example.com intitle:"Swagger UI" | inurl:"index.html" | inurl:"swagger" | inurl:"restapi" | inurl:"classicapi" | inurl:"api" | inurl:"apidocs" | inurl:api-docs | inurl:api-explorer | inurl:"clicktrack" | inurl:"doc" | inurl:"static" | inurl:"documentation" | inurl:"openapi" | inurl:"explore" | inurl:"v1" | inurl:"v2" | inurl:"v3" | inurl:"v4" | inurl:"developer" | inurl:"apidoc" | inurl:"document" | inurl:"govpay" | inurl:"routes" | inurl:"application" | inurl:"graphql" | inurl:"playground" | inurl:"apis" | inurl:"public" | inurl:"schema" | inurl:"spec" | inurl:"gateway"
```



### Test Environments

```
inurl:test | inurl:env | inurl:dev | inurl:staging | inurl:sandbox | inurl:debug | inurl:temp | inurl:internal | inurl:demo site:example.com
```

### Sensitive Documents

```
site:example.com ext:txt | ext:pdf | ext:xml | ext:xls | ext:xlsx | ext:ppt | ext:pptx | ext:doc | ext:docx
intext:“confidential” | intext:“Not for Public Release” | intext:”internal use only” | intext:“do not distribute”
```

### Sensitive Parameters

```
inurl:email= | inurl:phone= | inurl:password= | inurl:secret= inurl:& site:example[.]com
```

### Adobe Experience Manager (AEM)

```
inurl:/content/usergenerated | inurl:/content/dam | inurl:/jcr:content | inurl:/libs/granite | inurl:/etc/clientlibs | inurl:/content/geometrixx | inurl:/bin/wcm | inurl:/crx/de site:example[.]com
```

### Disclosed XSS and Open Redirects

```
site:openbugbounty.org inurl:reports intext:"example.com"
```

### Google Groups

```
site:groups.google.com "example.com"
```




### JFrog Artifactory

```
site:jfrog.io "example[.]com"
```

### Firebase

```
site:firebaseio.com "example[.]com"
```

## Dorks that work better w/o domain

### Bug Bounty programs and Vulnerability Disclosure Programs <!--omit-->

```
"submit vulnerability report" | "powered by bugcrowd" | "powered by hackerone"
```

```
site:*/security.txt "bounty"
```

### Apache Server Status Exposed <!--omit-->

```
site:*/server-status apache
```

### WordPress <!--omit-->

```
inurl:/wp-admin/admin-ajax.php
```

### Drupal <!--omit-->

```
intext:"Powered by" & intext:Drupal & inurl:user
```

### Joomla <!--omit-->

```
site:*/joomla/login
```


# github dorks 待去重


### api_key

```
https://github.com/search?q=example.com api_key
```

### app_AWS_SECRET_ACCESS_KEY

```
https://github.com/search?q=example.com app_AWS_SECRET_ACCESS_KEY
```

### app_secret

```
https://github.com/search?q=example.com app_secret
```

### authoriztion

```
https://github.com/search?q=example.com authoriztion
```

### Ldap

```
https://github.com/search?q=example.com Ldap
```

### aws_access_key_id

```
https://github.com/search?q=example.com aws_access_key_id
```

### secret

```
https://github.com/search?q=example.com secret
```

### .bash_history

```
https://github.com/search?q=example.com .bash_history
```

### bashrc password

```
https://github.com/search?q=example.com bashrc%20password
```

### beanstalkd.yml

```
https://github.com/search?q=example.com beanstalkd.yml
```

### client secret

```
https://github.com/search?q=example.com client secret
```

### composer.json

```
https://github.com/search?q=example.com composer.json
```

### config

```
https://github.com/search?q=example.com config
```

### credentials

```
https://github.com/search?q=example.com credentials
```

### DB_PASSWORD

```
https://github.com/search?q=example.com DB_PASSWORD
```

### deploy.rake

```
https://github.com/search?q=example.com deploy.rake
```

### dotfiles

```
https://github.com/search?q=example.com dotfiles
```

### .env

```
https://github.com/search?q=example.com .env
```

### .exs

```
https://github.com/search?q=example.com .exs
```

### extension:json mongolab.com

```
https://github.com/search?q=example.com extension:json mongolab.com
```

### extension:pem private

```
https://github.com/search?q=example.com extension:pem%20private
```

### extension:ppk private

```
https://github.com/search?q=example.com extension:ppk private
```

### extension:sql mysql dump

```
https://github.com/search?q=example.com extension:sql mysql dump
```

### extension:yaml mongolab.com

```
https://github.com/search?q=example.com extension:yaml mongolab.com
```

### filename:.bash_history

```
https://github.com/search?q=example.com filename:.bash_history
```

### filename:.bash_profile aws

```
https://github.com/search?q=example.com filename:.bash_profile aws
```

### filename:.bashrc mailchimp

```
https://github.com/search?q=example.com filename:.bashrc mailchimp
```

### filename:CCCam.cfg

```
https://github.com/search?q=example.com filename:CCCam.cfg
```

### filename:config irc_pass

```
https://github.com/search?q=example.com filename:config irc_pass
```

### filename:config.php dbpasswd

```
https://github.com/search?q=example.com filename:config.php dbpasswd
```

### filename:config.json auths

```
https://github.com/search?q=example.com filename:config.json auths
```

### filename:config.php pass

```
https://github.com/search?q=example.com filename:config.php pass
```

### filename:config.php dbpasswd

```
https://github.com/search?q=example.com filename:config.php dbpasswd
```

### filename:connections.xml

```
https://github.com/search?q=example.com filename:connections.xml
```

### filename:.cshrc

```
https://github.com/search?q=example.com filename:.cshrc
```

### filename:.git-credentials

```
https://github.com/search?q=example.com filename:.git-credentials
```

### filename:.ftpconfig

```
https://github.com/search?q=example.com filename:.ftpconfig
```

### filename:.history

```
https://github.com/search?q=example.com filename:.history
```

### filename:gitlab-recovery-codes.txt

```
https://github.com/search?q=example.com filename:gitlab-recovery-codes.txt
```

### filename:.htpasswd

```
https://github.com/search?q=example.com filename:.htpasswd
```

### filename:id_rsa

```
https://github.com/search?q=example.com filename:id_rsa
```

### filename:.netrc password

```
https://github.com/search?q=example.com filename:.netrc password
```

### FTP

```
https://github.com/search?q=example.com FTP
```

### filename:wp-config.php

```
https://github.com/search?q=example.com filename:wp-config.php
```

### git-credentials

```
https://github.com/search?q=example.com git-credentials
```

### github_token

```
https://github.com/search?q=example.com github_token
```

### HEROKU_API_KEY language:json

```
https://github.com/search?q=example.com HEROKU_API_KEY language:json
```

### HEROKU_API_KEY language:shell

```
https://github.com/search?q=example.com HEROKU_API_KEY language:shell
```

### HOMEBREW_GITHUB_API_TOKEN language:shell

```
https://github.com/search?q=example.com HOMEBREW_GITHUB_API_TOKEN language:shell
```

### .mlab.com password

```
https://github.com/search?q=example.com .mlab.com password
```

### mysql

```
https://github.com/search?q=example.com mysql
```

### npmrc _auth

```
https://github.com/search?q=example.com npmrc _auth
```

### oauth

```
https://github.com/search?q=example.com oauth
```

### OTP

```
https://github.com/search?q=example.com OTP
```

### pass

```
https://github.com/search?q=example.com pass
```

### passkey

```
https://github.com/search?q=example.com passkey
```

### passwd

```
https://github.com/search?q=example.com passwd
```

### password

```
https://github.com/search?q=example.com password
```

### databases password

```
https://github.com/search?q=example.com databases password
```

### rds.amazonaws.com password

```
https://github.com/search?q=example.com rds.amazonaws.com password
```

### s3cfg

```
https://github.com/search?q=example.com s3cfg
```

### send_key-keys

```
https://github.com/search?q=example.com send_key-keys
```

### token

```
https://github.com/search?q=example.com token
```

### [WFClient] Password= extension:ica

```
https://github.com/search?q=example.com [WFClient] Password= extension:ica
```

### xoxp OR xoxb OR xoxaJenkins

```
https://github.com/search?q=example.com xoxp%20OR%20xoxb%20OR%20xoxaJenkins
```

### security_credentials

```
https://github.com/search?q=example.com security_credentials
```



# shodan



### product:MySQL

```
https://www.shodan.io/search?query=example.com product:MySQL
```

### "MongoDB Server Information" -authentication

```
https://www.shodan.io/search?query=example.com "MongoDB Server Information" -authentication
```

### "default password"

```
https://www.shodan.io/search?query=example.com "default password"
```

### guest login ok

```
https://www.shodan.io/search?query=example.com guest login ok
```

### x-jenkins 200

```
https://www.shodan.io/search?query=example.com x-jenkins 200
```

### http.html:"* The wp-config.php creation script uses this file"

```
https://www.shodan.io/search?query=example.com http.html:"* The wp-config.php creation script uses this file"
```

### "root@" port:23 -login -password -name -Session

```
https://www.shodan.io/search?query=example.com "root@" port:23 -login -password -name -Session
```

### html:"def_wirelesspassword"

```
https://www.shodan.io/search?query=example.com html:"def_wirelesspassword"
```

### "authentication disabled"

```
https://www.shodan.io/search?query=example.com "authentication disabled"
```

### "authentication disabled" "RFB 003.008"

```
https://www.shodan.io/search?query=example.com "authentication disabled" "RFB 003.008"
```

### http.title:"dashboard"

```
https://www.shodan.io/search?query=example.com http.title:"dashboard"
```

### http.title:"control panel"

```
https://www.shodan.io/search?query=example.com http.title:"control panel"
```

### http.title:"phpmyadmin"

```
https://www.shodan.io/search?query=example.com http.title:"phpmyadmin"
```

### product:"CouchDB"

```
https://www.shodan.io/search?query=example.com product:"CouchDB"
```

### kibana content-length:217

```
https://www.shodan.io/search?query=example.com kibana content-length:217
```

### http.title:outlook exchange

```
https://www.shodan.io/search?query=example.com http.title:outlook exchange
```

### http.favicon.hash:1398055326

```
https://www.shodan.io/search?query=example.com http.favicon.hash:1398055326
```

### http.html:WSO2

```
https://www.shodan.io/search?query=example.com http.html:WSO2
```

### "webvpn="

```
https://www.shodan.io/search?query=example.com "webvpn="
```

### port:"445" os:"Windows"

```
https://www.shodan.io/search?query=example.com port:"445" os:"Windows"
```

### http.favicon.hash:-1250474341

```
https://www.shodan.io/search?query=example.com http.favicon.hash:-1250474341
```

### http.html:"xoxb-"

```
https://www.shodan.io/search?query=example.com http.html:"xoxb-"
```

### http.favicon.hash:81586312

```
https://www.shodan.io/search?query=example.com http.favicon.hash:81586312
```

### http.title:"Grafana"

```
https://www.shodan.io/search?query=example.com http.title:"Grafana"
```

### http.html:zabbix

```
https://www.shodan.io/search?query=example.com http.html:zabbix
```

### http.html:Horde:

```
https://www.shodan.io/search?query=example.com http.html:Horde:
```

### http.title:"Argo CD"

```
https://www.shodan.io/search?query=example.com http.title:"Argo CD"
```

### product:tomcat

```
https://www.shodan.io/search?query=example.com product:tomcat
```

### port:23 console gateway

```
https://www.shodan.io/search?query=example.com port:23 console gateway
```

### "\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00"

```
https://www.shodan.io/search?query=example.com "\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00"
```

### proftpd port:21

```
https://www.shodan.io/search?query=example.com proftpd port:21
```

### http.html:/dana-na/

```
https://www.shodan.io/search?query=example.com http.html:/dana-na/
```

### http.title:"BIG-IP&reg;-Redirect"

```
https://www.shodan.io/search?query=example.com http.title:"BIG-IP&reg;-Redirect"
```

### "unauthorized"

```
https://www.shodan.io/search?query=example.com "unauthorized"
```

### "Set-Cookie: mongo-express=" "200 OK"

```
https://www.shodan.io/search?query=example.com "Set-Cookie: mongo-express=" "200 OK"
```

### "X-Jenkins" "Set-Cookie: JSESSIONID" http.title:"Dashboard"

```
https://www.shodan.io/search?query=example.com "X-Jenkins" "Set-Cookie: JSESSIONID" http.title:"Dashboard"
```

### "Intel(R) Active Management Technology" port:623,664,16992,16993,16994,16995

```
https://www.shodan.io/search?query=example.com "Intel(R) Active Management Technology" port:623,664,16992,16993,16994,16995
```

### http.title:"Index of /" http.html:".pem"

```
https://www.shodan.io/search?query=example.com http.title:"Index of /" http.html:".pem"
```

### "Serial Number:" "Built:" "Server: HP HTTP"

```
https://www.shodan.io/search?query=example.com "Serial Number:" "Built:" "Server: HP HTTP"
```
