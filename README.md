
## > Google Dorks

### subdomain

```
site:*.example.com | site:*.*.example.com
```

```
site:subdomainfinder.c99.nl inurl:example.com
```

### EMAIL - - > 所有联系邮箱
```
site:example.com (filetype:doc OR filetype:xlsx) intext:@gmail.com
```

### Code Leaks - - > 外链研究

```
site:pastebin.com | site:paste2.org | site:pastehtml.com | site:slexy.org | site:snipplr.com | site:snipt.net | site:textsnip.com | site:bitpaste.app | site:justpaste.it | site:heypasteit.com | site:hastebin.com | site:dpaste.org | site:dpaste.com | site:codepad.org | site:jsitor.com | site:codepen.io | site:jsfiddle.net | site:dotnetfiddle.net | site:phpfiddle.org | site:ide.geeksforgeeks.org | site:repl.it | site:ideone.com | site:paste.debian.net | site:paste.org | site:paste.org.ru | site:codebeautify.org  | site:codeshare.io | site:trello.com "example.com"
```

### Doc Leaks 

```
site:docs.google.com inurl:"/d/" "example.com"
```

### Cloud Storage Leaks - - > 有时这些site需要拆开各自单独和关键词组合

```
site:s3.amazonaws.com | site:blob.core.windows.net | site:googleapis.com | site:drive.google.com | site:dev.azure.com | site:onedrive.live.com | site:digitaloceanspaces.com | site:sharepoint.com | site:s3-external-1.amazonaws.com | site:s3.dualstack.us-east-1.amazonaws.com | site:dropbox.com/s | site:box.com/s "example.com"
```

### Search in 3rd Party Vendors

```
site:scribd.com | site:npmjs.com | site:npm.runkit.com | site:libraries.io | site:coggle.it | site:papaly.com | site:prezi.com | site:jsdelivr.net | site:gitter.im "example.com"
```

### Publicly Exposed Documents

```
ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv | ext:xls | ext:xlsx | ext:txt site:example.com
```

### robots & sitemap

```
ext:txt | ext:xml | inurl:robots | inurl:sitemap | intext:robots | intext:sitemap site:example.com
```

### Important Dorks

```
site:example.com filetype:txt | inurl:.php.txt | ext:txt
```

### Linkedin Employees

```
site:linkedin.com employees "example.com"
```

### Form pages

```
intitle:"Submit Feedback" | intitle:"Contact us" | intitle:"Join Our Waitlist" | intitle:"Subscribe" | intitle:"Newsletter" | intitle:"Unsubscribe" | intitle:"Email Support" | intitle:"Customer Support" site:example.com
```

### Login Pages

```
inurl:login | inurl:signin | intitle:login | intitle:"sign in" | inurl:secure | inurl:auth | inurl:/register | inurl:portal site:example.com
```

### INDEX

```
intext:"index of" | "parent directory" | intitle:index.of site:example.com
```

### Search in github/gitlab/StackOverflow

```
site:github.com | site:gitlab.com | site:stackoverflow.com "example.com"
```

### Find Repository

```
intext:'index of' 'repository' inurl:example.com
```

### WordPress

```
site:example.com inurl:wp- | inurl:wp-content | inurl:wp-admin | inurl:wp-includes | inurl:plugins | inurl:uploads | inurl:themes | inurl:download
```

### Wordpress Juicy file 1

```
inurl:/wp-content/uploads/wpo_wcpdf "example.com"
```

### Wordpress Juicy file 2

```
inurl:wp-content/uploads/wcpa_uploads "example.com"
```

### Wordpress Juicy file 3

```
inurl:"wp-content" intitle:"index.of" intext:wp-config.php "example.com"
```

### Vulnerable Wordpress Plugin

```
inurl:*/wp-content/plugins/contact-form-7/ "example.com"
```

### Wordpress Backup

```
inurl:"wp-content" intitle:"index.of" intext:backup" "example.com"
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

### wp-content Juicy Info

```
inurl:/wp-content/uploads/wpo_wcpdf "example.com"
```

### WordPress admin panel

```
inurl:/wp-admin/admin-ajax.php "example.com"
```

### Drupal - - > Drupal是一个开源的内容管理系统（CMS）

```
"example.com" intext:"Powered by" & intext:Drupal & inurl:user
```

### Drupal Login

```
"example.com" inurl:user intitle:"Drupal" intext:"Log in" -"powered by"
```

### Joomla - - > Joomla是一个开源的内容管理系统（CMS）

```
site:*/joomla/login "example.com"
```

### JOOMLA
```
site:example.com intext:"Joomla! - Open Source Content Management"
```

```
site:example.com site:*/joomla/administrator
```

### Joomla Database/

```
inurl: /libraries/joomla/database/ "example.com"
```

### Password files

```
site:example.com "password" filetype:doc | filetype:pdf | filetype:docx | filetype:xls | filetype:dat | filetype:log
```

### Config and log files

```
site:example.com ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini | ext:log
```

### Backup and old files

```
site:example.com ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup
```

### Apache Config Files

```
site:example.com filetype:config 'apache'
```

### Find HTML Files

```
intext:'index of' '.html' inurl:example.com
```

### Install / Setup files

```
inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config "example.com"
```

### main.yml file

```
intitle:"index of "main.yml"" "example.com"
```

### File Upload

```
inurl:uploadimage.php "example.com"
```

### jwks-rsa file

```
intext:"index of" inurl:jwks-rsa "example.com"
```

### Docker-Compose yml file

```
intitle:"index of" "docker-compose.yml" "example.com"
```

### PHP extension w/ parameters

```
site:example.com ext:php inurl:?
```

### phpinfo()

```
site:example.com ext:php intitle:phpinfo 'published by the PHP Group'
```

### PHP errors / warning

```
site:example.com 'PHP Parse error' | 'PHP Warning' | 'PHP Error'
```

### Find SWF

```
+inurl: +ext:swf "example.com"
```

### Find MIME-SWF

```
site: mime:swf "example.com"
```

### Firebase

```
site:firebaseio.com "example.com"
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

### Database related

```
site:example.com intext:'sql syntax near' | intext:'syntax error has occurred' | intext:'incorrect syntax near' | intext:'unexpected end of SQL command' | intext:'Warning: mysql_connect()' | intext:'Warning: mysql_query() | intext:'Warning: pg_connect()' | filetype:sql | ext:sql | ext:dbf | ext:mdb
```

### SQL errors

```
site:example.com intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"
```

### Mysql file

```
intitle:index.of conf.mysql "example.com"
```

### Sql File

```
inurl:"php?sql=select" ext:php "example.com"
```

### Git Leaks

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
site:example.com filetype:git -github.com inurl:"/.git"
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

### log Leaks

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

### Sensitive Documents

```
site:example.com ext:txt | ext:pdf | ext:xml | ext:xls | ext:xlsx | ext:ppt | ext:pptx | ext:doc | ext:docx
intext:“confidential” | intext:“Not for Public Release” | intext:”internal use only” | intext:“do not distribute”
```

### Sensitive Parameters

```
inurl:email= | inurl:phone= | inurl:password= | inurl:secret= inurl:& site:example.com
```

### .htaccess - - > .htaccess文件是Apache Web 服务器的配置文件

```
site:example.com intext:"Index of /" +.htaccess
```

```
inurl:"/phpinfo.php" | inurl:".htaccess" | inurl:"/.git"  -github "example.com"
```

### Sensitive File

```
intitle:index.of conf.php "example.com"
```

### Sensitive Admin Backup

```
intitle:"Index of" inurl:/backup/ "admin.zip" "example.com"
```

### Sensitive File

```
intitle:"index of" "download.php?file=" "example.com"
```

### Sensitive File

```
intitle:"index of" "users.yml" | "admin.yml" | "config.yml" "example.com"
```

### Sensitive File

```
intext:pom.xml intitle:"index of /" "example.com"
```

### Sensitive File

```
intext:"Index of" intext:"/etc" "example.com"
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

### Disclosed XSS and Open Redirects

```
site:openbugbounty.org inurl:reports intext:"example.com"
```

### OPEN REDIRECT PARAMETERS
```
site:example.com inurl:url= | inurl:return= | inurl:next= | inurl:redirect= | inurl:redir= | inurl:ret= | inurl:r2= | inurl:page= inurl:& inurl:http
```

```
site:example.com inurl:(url= | return= | next= | redirect= | redir= | ret= | r2= | page=) inurl:& inurl:http
```

```
inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http site:example.com
```

### XSS prone parameters

```
site:example.com inurl:& inurl:q= | inurl:s= | inurl:search= | inurl:query= | inurl:keyword= | inurl:lang=
```

### SQLI Prone Parameters

```
site:example.com inurl:& inurl:id= | inurl:pid= | inurl:category= | inurl:cat= | inurl:action= | inurl:sid= | inurl:dir=
```

### SSRF Prone Parameters

```
inurl:http | inurl:url= | inurl:path= | inurl:dest= | inurl:html= | inurl:data= | inurl:domain=  | inurl:page= inurl:& site:example.com
```

```
site:example.com inurl:include | inurl:dir | inurl:detail= | inurl:file= | inurl:folder= | inurl:inc= | inurl:locate= | inurl:doc= | inurl:conf= inurl:&
```

### LFI Prone Parameters

```
inurl:include | inurl:dir | inurl:detail= | inurl:file= | inurl:folder= | inurl:inc= | inurl:locate= | inurl:doc= | inurl:conf= inurl:& site:example.com
```

### RCE Prone Parameters

```
site:example.com inurl:& inurl:cmd | inurl:exec= | inurl:query= | inurl:code= | inurl:do= | inurl:run= | inurl:read= | inurl:ping=
```

### Test Environments

```
inurl:test | inurl:env | inurl:dev | inurl:staging | inurl:sandbox | inurl:debug | inurl:temp | inurl:internal | inurl:demo site:example.com
```

### JFrog Artifactory

```
site:jfrog.io "example.com"
```

### OPENBUGBOUNTY REPORTS
```
site:openbugbounty.org inurl:reports intext:"example.com"
```

### ATLASSIAN
```
site:example.com inurl:Dashboard.jspa intext:"Atlassian Jira Project Management Software"
```

### BACKEND
```
site:example.com intext:"Index of" intext:"backend/"
```

### Finding Backdoors

```
inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini "example.com"
```

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

### SOURCE-CODE
```
site:example.com Index of" intext:"source_code.zip | Index of" intext:"zip
```

### DOCKER-COMPOSE
```
site:example.com intitle:"index of" "docker-compose.yml"
```

### JUICY EXTENSIONS
```
site:example.com ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess
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

### PHP ERROR
```
site:example.com "PHP Parse error" | "PHP Warning" | "PHP Error"
```

### KIBANA
```
site:example.com inurl:"/app/kibana#"
```

### Vulnerable Servers

```
inurl:"/geoserver/ows?service=wfs" "example.com"
```

### ArcGIS REST Services Directory

```
intext:"ArcGIS REST Services Directory" intitle:"Folder: /" "example.com"
```

### Admin Portal

```
inurl:/admin.aspx "example.com"
```

### Sharing API Info

```
intitle:"Sharing API Info" "example.com"
```

### Github API

```
intitle:"index of" github-api "example.com"
```

### Remote procedure call protocol

```
intext:"index of" inurl:json-rpc "example.com"
```

### Directories containing SQL Installs and/or SQL databases

```
"sql" "parent" intitle:index.of -injection "example.com"
```
### API Endpoints

```
site:example.com inurl:api | site:*/rest | site:*/v1 | site:*/v2 | site:*/v3
```

### Shodan Api

```
inurl:pastebin 'SHODAN_API_KEY' "example.com"
```

### High % inurl keywords

```
inurl:conf | inurl:env | inurl:cgi | inurl:bin | inurl:etc | inurl:root | inurl:sql | inurl:backup | inurl:admin | inurl:php site:example.com
```

### Server Errors

```
inurl:"error" | intitle:"exception" | intitle:"failure" | intitle:"server at" | inurl:exception | "database error" | "SQL syntax" | "undefined index" | "unhandled exception" | "stack trace" site:example.com
```

### Error Log Source Code

```
'index of' error_log intext:example.com
```

### File upload endpoints

```
site:example.com ”choose file”
```

### SWAGGER-UI

```
site:example.com intitle:"Swagger UI" | inurl:"index.html" | inurl:"swagger" | inurl:"restapi" | inurl:"classicapi" | inurl:"api" | inurl:"apidocs" | inurl:api-docs | inurl:api-explorer | inurl:"clicktrack" | inurl:"doc" | inurl:"static" | inurl:"documentation" | inurl:"openapi" | inurl:"explore" | inurl:"v1" | inurl:"v2" | inurl:"v3" | inurl:"v4" | inurl:"developer" | inurl:"apidoc" | inurl:"document" | inurl:"govpay" | inurl:"routes" | inurl:"application" | inurl:"graphql" | inurl:"playground" | inurl:"apis" | inurl:"public" | inurl:"schema" | inurl:"spec" | inurl:"gateway"
```

### Adobe Experience Manager (AEM)

```
inurl:/content/usergenerated | inurl:/content/dam | inurl:/jcr:content | inurl:/libs/granite | inurl:/etc/clientlibs | inurl:/content/geometrixx | inurl:/bin/wcm | inurl:/crx/de site:example.com
```

### IIS Windows Server

```
intitle:'IIS Windows Server' "example.com"
```

### Apache Server Status Exposed

```
site:*/server-status apache "example.com"
```

### Google Groups

```
site:groups.google.com "example.com"
```

### .git folder

```
inurl:'/.git 'example.com -github
```

### Digital Ocean Spaces

```
site:digitaloceanspaces.com "example.com"
```

### Apache Struts RCE

```
site:example.com ext:action | ext:struts | ext:do
```

### Search in Bitbucket and Atlassian

```
site:bitbucket.org | site:atlassian.net "example.com"
```

### MY CUSTOM DORK
```
site:example.com intext:"Index of" intext:"database.sql"
```

```
site:example.com intext:"Index of" intext:"admin.tar.gz"
```


## > Github Dorks

### Search in GITHUB

```
https://github.com/search?q=%22example.com%22&type=Code
```

### Search in Github Gist

```
https://gist.github.com/search?q=%22example.com%22
```

### Find Github password

```
https://github.com/search?q=%22example.com%22+password&type=Code
```

```
https://github.com/search?q=%22example.com%22+pass&type=Code
```

```
https://github.com/search?q=%22example.com%22+passkey&type=Code
```

```
https://github.com/search?q=%22example.com%22+passwd&type=Code
```

### path:*/config.php pass

```
https://github.com/search?q=%22example.com%22+path%3A*%2Fconfig.php+pass&type=Code
```

### Find Github htpasswd

```
https://github.com/search?q=%22example.com%22+htpasswd&type=Code
```

### databases password

```
https://github.com/search?q=%22example.com%22+password+database&type=Code
```

### DB_PASSWORD

```
https://github.com/search?q=%22example.com%22+DB_PASSWORD&type=Code
```

### path:*/config.php dbpasswd

```
https://github.com/search?q=%22example.com%22+dbpasswd+path%3A*%2Fconfig.php&type=code
```

### path:*/.netrc password

```
https://github.com/search?q=%22example.com%22+path%3A*%2F.netrc+password&type=Code
```

### rds.amazonaws.com password

```
https://github.com/search?q=%22example.com%22+password+rds.amazonaws.com&type=Code
```

### .mlab.com password - - > .mlab.com 通常是 MongoDB 数据库的配置文件

```
https://github.com/search?q=%22example.com%22+.mlab.com+password&type=Code
```

### Find Github bashrc password - - > bashrc 通常是 Bash 脚本的配置文件

```
https://github.com/search?q=%22example.com%22+bashrc%20password&type=Code
```

### [WFClient] Password= path:*.ica - - > [WFClient] 通常是 Workfront 客户端的配置文件

```
https://github.com/search?q=%22example.com%22+[WFClient]+Password=+path%3A*ica&type=Code
```

### authoriztion

```
https://github.com/search?q=%22example.com%22+authoriztion&type=Code
```

### oauth

```
https://github.com/search?q=%22example.com%22+oauth&type=Code
```

### .json auth - - > language 指代文件类型，可以替换为path:*.json

```
https://github.com/search?q=%22example.com%22+language%3Ajson+auth&type=Code
```

### Find Github npmrc _auth - - > npmrc 通常是 npm 包管理器的配置文件

```
https://github.com/search?q=%22example.com%22+npmrc%20_auth&type=Code
```

### Find Github credentials - - > credentials 通常是 OAuth 2.0 授权流程中的客户端密钥

```
https://github.com/search?q=%22example.com%22+credentials&type=Code
```

### security_credentials

```
https://github.com/search?q=%22example.com%22+security_credentials&type=Code
```

### Find Github git-credentials

```
https://github.com/search?q=%22example.com%22+git-credentials&type=Code
```

### path:*/.git-credentials - - >.git-credentials 通常是 Git 版本控制系统的配置文件

```
https://github.com/search?q=%22example.com%22+path%3A*%2F.git-credentials&type=Code
```

### Find Github sshd_config - - > sshd_config 通常是 SSH 服务器的配置文件

```
https://github.com/search?q=%22example.com%22+sshd_config&type=Code
```

### Find Github xoxp OR xoxb OR xoxaJenkins - -> xoxp OR xoxb OR xoxa 通常是 Slack 令牌

```
https://github.com/search?q=%22example.com%22+xoxp+OR+xoxb+OR+xoxa&type=Code
```

### Find Github github_token

```
https://github.com/search?q=%22example.com%22+github_token&type=Code
```

### token

```
https://github.com/search?q=%22example.com%22+token&type=Code
```

### Find Github api_key

```
https://github.com/search?q=%22example.com%22+api_key&type=Code
```

### HEROKU_API_KEY language:json

```
https://github.com/search?q=%22example.com%22+HEROKU_API_KEY+language%3Ajson+&type=Code
```

### HEROKU_API_KEY language:shell

```
https://github.com/search?q=%22example.com%22+HEROKU_API_KEY+language%3Ashell+&type=Code
```

### HOMEBREW_GITHUB_API_TOKEN language:shell

```
https://github.com/search?q=%22example.com%22+HOMEBREW_GITHUB_API_TOKEN+language%3Ashell+&type=Code
```

### Find Github SECRET_KEY 

```
https://github.com/search?q=%22example.com%22+SECRET_KEY&type=Code
```

### aws_access_key_id - - > aws_access_key_id 通常是 AWS 访问密钥的 ID

```
https://github.com/search?q=%22example.com%22+aws_access_key_id&type=Code
```

### send_key-keys - - > send_key-keys 通常是 OAuth 2.0 授权流程中的客户端密钥

```
https://github.com/search?q=%22example.com%22+send_key-keys&type=Code
```

### Find Github OTP - - > OTP 通常是一次性密码

```
https://github.com/search?q=%22example.com%22+OTP&type=Code
```

### Find Github secrets - - > secrets 通常是 OAuth 2.0 授权流程中的客户端密钥

```
https://github.com/search?q=%22example.com%22+secrets&type=Code
```

### Find Github app_secret - - > app_secret 通常是 OAuth 2.0 授权流程中的客户端密钥

```
https://github.com/search?q=%22example.com%22+app_secret&type=Code
```

### client secret - - > client secret 通常是 OAuth 2.0 授权流程中的客户端密钥

```
https://github.com/search?q=%22example.com%22+client%20secret&type=Code
```

### path:*.ppk private - - > ppk 通常是 PuTTY 私钥文件

```
https://github.com/search?q=%22example.com%22+path%3A*ppk%20private&type=Code
```

### id_rsa - - > id_rsa 通常是 SSH 密钥对中的私钥文件

```
https://github.com/search?q=%22example.com%22+id_rsa&type=Code
```

### path:*.pem private - - > pem 通常是 SSL/TLS 证书的文件

```
https://github.com/search?q=%22example.com%22+path%3A*pem%20private&type=Code
```

### path:*/.history - - > .history 通常是 Unix/Linux 系统的历史命令记录文件

```
https://github.com/search?q=%22example.com%22+path%3A*%2F.history&type=Code
```

### .bash_history - - > .bash_history 通常是 Unix/Linux 系统的历史命令记录文件

```
https://github.com/search?q=%22example.com%22+.bash_history&type=Code
```

### config - - > config 通常是配置文件

```
https://github.com/search?q=%22example.com%22+config&type=Code
```

### path:*/wp-config.php - - > wp-config.php 通常是 WordPress 网站的配置文件

```
https://github.com/search?q=%22example.com%22+path%3A*%2Fwp-config.php&type=Code
```

### dockercfg - - > dockercfg 通常是 Docker 客户端的配置文件

```
https://github.com/search?q=%22example.com%22+dockercfg&type=Code
```

### Find Github FTP - - > FTP 通常是 FTP 服务器的配置文件

```
https://github.com/search?q=%22example.com%22+FTP&type=Code
```

### Find Github PWD - - > PWD 通常是 FTP 服务器的配置文件

```
https://github.com/search?q=%22example.com%22+PWD&type=Code
```

### path:*/.ftpconfig - - > .ftpconfig 通常是 FTP 客户端的配置文件

```
https://github.com/search?q=%22example.com%22+path%3A*%2F.ftpconfig&type=Code
```

### dotfiles - - > dotfiles 通常是用户的配置文件

```
https://github.com/search?q=%22example.com%22+dotfiles&type=Code
```

### .env - - >.env 通常是环境变量的配置文件

```
https://github.com/search?q=%22example.com%22+.env&type=Code
```

### .exs - - > .exs 通常是 Ruby on Rails 项目中用于配置的文件

```
https://github.com/search?q=%22example.com%22+.exs&type=Code
```

### Ldap - - > Ldap 通常是 LDAP 服务器的配置文件

```
https://github.com/search?q=%22example.com%22+Ldap&type=Code
```

### Find Github .sls - - > .sls 通常是 SaltStack 配置文件

```
https://github.com/search?q=%22example.com%22+.sls&type=Code
```

### composer.json - - > composer.json 通常是 PHP 项目的依赖管理文件

```
https://github.com/search?q=%22example.com%22+composer.json&type=Code
```

### deploy.rake - - > deploy.rake 通常是 Ruby on Rails 项目中用于部署任务的文件

```
https://github.com/search?q=%22example.com%22+deploy.rake&type=Code
```

### Find Github mysql - - > mysql 通常是 MySQL 数据库的配置文件

```
https://github.com/search?q=%22example.com%22+mysql&type=Code
```

### path:*.sql mysql dump - - > mysql dump 通常是 MySQL 数据库的备份文件

```
https://github.com/search?q=%22example.com%22+path%3A*sql+mysql+dump&type=Code
```

### path:*/connections.xml - - > connections.xml 通常是 MySQL 数据库的连接配置文件

```
https://github.com/search?q=%22example.com%22+path%3A*%2Fconnections.xml&type=Code
```

### path:*.yaml mongolab.com - - > MongoDB 数据库的配置文件

```
https://github.com/search?q=%22example.com%22+path%3A*.yaml+mongolab.com&type=code
```

### path:*.json mongolab.com - - > MongoDB 数据库的配置文件

```
https://github.com/search?q=%22example.com%22+path%3A*json+mongolab.com&type=Code
```

### Find Github s3.yml - - > s3.yml 通常是 AWS S3 存储服务的配置文件

```
https://github.com/search?q=%22example.com%22+.env&type=Code
```

### path:*/.bash_profile aws - - > aws 通常是 Amazon Web Services 的配置文件

```
https://github.com/search?q=%22example.com%22+path%3A*%2F.bash_profile+aws&type=Code
```

### path:*/.bashrc mailchimp - - > mailchimp 通常是邮件营销平台的配置文件

```
https://github.com/search?q=%22example.com%22+path%3A*%2F.bashrc+mailchimp&type=Code
```

### path:*/config irc_pass - - > irc_pass 通常是 IRC 客户端的配置文件

```
https://github.com/search?q=%22example.com%22+path%3A*%2Fconfig+irc_pass&type=Code
```

### beanstalkd.yml - - > beanstalkd.yml 通常是 Beanstalkd 消息队列的配置文件

```
https://github.com/search?q=%22example.com%22+beanstalkd.yml&type=Code
```

### path:*/CCCam.cfg - - > CCCam.cfg 通常是 Cisco 设备的配置文件

```
https://github.com/search?q=%22example.com%22+path%3A*%2FCCCam.cfg&type=Code
```

### s3cfg - - > s3cfg 通常是 Amazon S3 客户端的配置文件

```
https://github.com/search?q=%22example.com%22+s3cfg&type=Code
```

### path:*/.cshrc - - > .cshrc 通常是 C shell 的配置文件

```
https://github.com/search?q=%22example.com%22+path%3A*%2F.cshrc&type=Code
```

### path:*/gitlab-recovery-codes.txt - - >  GitLab 网站的恢复码文件

```
https://github.com/search?q=%22example.com%22+path%3A*%2Fgitlab-recovery-codes.txt&type=Code
```


## > Shodan Dorks

### Search in Shodan

```
https://www.shodan.io/search?query=example.com
```

### product:MySQL - - > 查询MySQL产品

```
https://www.shodan.io/search?query=example.com+product%3AMySQL
```

### "MongoDB Server Information" -authentication - - > 查询MongoDB服务器信息，排除认证

```
https://www.shodan.io/search?query=example.com "MongoDB Server Information" -authentication
```

### "default password" - - > 查询默认密码

```
https://www.shodan.io/search?query=example.com%20%22default%20password%22
```

### guest login ok - - > 查询允许游客登录

```
https://www.shodan.io/search?query=example.com%20guest%20login%20ok
```

### x-jenkins 200 - - > 查询Jenkins服务状态码为200

```
https://www.shodan.io/search?query=example.com%20x-jenkins%20200
```

### http.html:"* The wp-config.php creation script uses this file" - - > 查询包含wp-config.php创建脚本的页面

```
https://www.shodan.io/search?query=example.com%20http.html:%22*%20The%20wp-config.php%20creation%20script%20uses%20this%20file%22
```

### "root@" port:23 -login -password -name -Session - - > 查询23端口root用户，排除登录、密码、名称和会话

```
https://www.shodan.io/search?query=example.com%20%22root@%22%20port:23%20-login%20-password%20-name%20-Session
```

### html:"def_wirelesspassword" - - > 查询包含默认无线密码的页面

```
https://www.shodan.io/search?query=example.com%20html:%22def_wirelesspassword%22
```

### "authentication disabled" - - > 查询认证禁用的服务

```
https://www.shodan.io/search?query=example.com%20%22authentication%20disabled%22
```

### "authentication disabled" "RFB 003.008" - - > 查询VNC认证禁用的服务

```
https://www.shodan.io/search?query=example.com%20%22authentication%20disabled%22%20%22RFB%20003.008%22
```

### http.title:"dashboard" - - > 查询标题包含dashboard的页面

```
https://www.shodan.io/search?query=example.com%20http.title:%22dashboard%22
```

### http.title:"control panel" - - > 查询标题包含control panel的页面

```
https://www.shodan.io/search?query=example.com%20http.title:%22control%20panel%22
```

### http.title:"phpmyadmin" - - > 查询标题包含phpmyadmin的页面

```
https://www.shodan.io/search?query=example.com%20http.title:%22phpmyadmin%22
```

### product:"CouchDB" - - > 查询CouchDB产品

```
https://www.shodan.io/search?query=example.com%20product:%22CouchDB%22
```

### kibana content-length:217 - - > 查询Kibana内容长度为217的服务

```
https://www.shodan.io/search?query=example.com%20kibana%20content-length:217
```

### http.title:outlook exchange - - > 查询标题包含outlook exchange的页面

```
https://www.shodan.io/search?query=example.com%20http.title:outlook%20exchange
```

### http.favicon.hash:1398055326 - - > 查询特定favicon哈希值的服务

```
https://www.shodan.io/search?query=example.com%20http.favicon.hash:1398055326
```

### http.html:WSO2 - - > 查询页面包含WSO2的服务

```
https://www.shodan.io/search?query=example.com%20http.html:WSO2
```

### "webvpn=" - - > 查询包含webvpn=的页面

```
https://www.shodan.io/search?query=example.com%20%22webvpn=%22
```

### port:"445" os:"Windows" - - > 查询445端口的Windows系统

```
https://www.shodan.io/search?query=example.com%20port:%22445%22%20os:%22Windows%22
```

### http.favicon.hash:-1250474341 - - > 查询特定favicon哈希值的服务

```
https://www.shodan.io/search?query=example.com%20http.favicon.hash:-1250474341
```

### http.html:"xoxb-" - - > 查询页面包含xoxb-的服务

```
https://www.shodan.io/search?query=example.com%20http.html:%22xoxb-%22
```

### http.favicon.hash:81586312 - - > 查询特定favicon哈希值的服务

```
https://www.shodan.io/search?query=example.com%20http.favicon.hash:81586312
```

### http.title:"Grafana" - - > 查询标题包含Grafana的页面

```
https://www.shodan.io/search?query=example.com%20http.title:%22Grafana%22
```

### http.html:zabbix - - > 查询页面包含zabbix的服务

```
https://www.shodan.io/search?query=example.com%20http.html:zabbix
```

### http.html:Horde: - - > 查询页面包含Horde:的服务

```
https://www.shodan.io/search?query=example.com%20http.html:Horde:
```

### http.title:"Argo CD" - - > 查询标题包含Argo CD的页面

```
https://www.shodan.io/search?query=example.com%20http.title:%22Argo%20CD%22
```

### product:tomcat - - > 查询Tomcat产品

```
https://www.shodan.io/search?query=example.com%20product:tomcat
```

### port:23 console gateway - - > 查询23端口的console gateway

```
https://www.shodan.io/search?query=example.com%20port:23%20console%20gateway
```

### "\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00" - - > 查询包含特定十六进制序列的服务

```
https://www.shodan.io/search?query=example.com%20%22%5Cx03%5Cx00%5Cx00%5Cx0b%5Cx06%5Cxd0%5Cx00%5Cx00%5Cx124%5Cx00%22
```

### proftpd port:21 - - > 查询21端口的ProFTPd服务

```
https://www.shodan.io/search?query=example.com%20proftpd%20port:21
```

### http.html:/dana-na/ - - > 查询页面包含/dana-na/的服务

```
https://www.shodan.io/search?query=example.com%20http.html:/dana-na/
```

### http.title:"BIG-IP&reg;-Redirect" - - > 查询标题包含BIG-IP&reg;-Redirect的页面

```
https://www.shodan.io/search?query=example.com%20http.title:%22BIG-IP%C2%AE-Redirect%22
```

### "unauthorized" - - > 查询未经授权的服务

```
https://www.shodan.io/search?query=example.com%20%22unauthorized%22
```

### "Set-Cookie: mongo-express=" "200 OK" - - > 查询设置mongo-express cookie且返回200 OK的服务

```
https://www.shodan.io/search?query=example.com%20%22Set-Cookie:%20mongo-express=%22%20%22200%20OK%22
```

### "X-Jenkins" "Set-Cookie: JSESSIONID" http.title:"Dashboard" - - > 查询包含X-Jenkins头、JSESSIONID cookie且标题包含Dashboard的服务

```
https://www.shodan.io/search?query=example.com%20%22X-Jenkins%22%20%22Set-Cookie:%20JSESSIONID%22%20http.title:%22Dashboard%22
```

### "Intel(R) Active Management Technology" port:623,664,16992,16993,16994,16995 - - > 查询Intel AMT技术在特定端口上的服务

```
https://www.shodan.io/search?query=example.com%20%22Intel(R)%20Active%20Management%20Technology%22%20port:623,664,16992,16993,16994,16995
```

### http.title:"Index of /" http.html:".pem" - - > 查询标题包含"Index of /"且页面包含".pem"的服务

```
https://www.shodan.io/search?query=example.com%20http.title:%22Index%20of%20/%22%20http.html:%22.pem%22
```

### "Serial Number:" "Built:" "Server: HP HTTP" - - > 查询包含HP HTTP服务器信息（序列号、构建日期）的服务

```
https://www.shodan.io/search?query=example.com%20%22Serial%20Number:%22%20%22Built:%22%20%22Server:%20HP%20HTTP%22
```


## > others

### Google CSE

```
https://cse.google.com/cse?cx=002972716746423218710:veac6ui3rio#gsc.tab=0&gsc.q=example.com
```

### Search in Reddit

```
https://www.reddit.com/search/?q=example.com&source=recent
```

### What CMS?

```
https://whatcms.org/?s=example.com
```

### Certificate Transparency #1

```
https://crt.sh/?q=example.com
```

### Certificate Transparency #2 - - > 在crt.sh的规则中，%25代表通配符

```
https://crt.sh/?q=%25.example.com
```

### Wayback Machine #1

```
https://web.archive.org/web/*/example.com/*
```

### Wayback Machine #2 - - > 在Wayback Machine的规则中，*代表通配符

```
https://web.archive.org/web/*/*.example.com/*
```

### Search in Rapiddns Subdomain - - > 用于查找特定域名的子域名

```
https://rapiddns.io/subdomain/example.com?full=1#result
```

### Search in Virustotal Subdomain - - > 用于查找特定域名的子域名

```
https://www.virustotal.com/gui/domain/example.com/relations
```

### Reverse ip lookup - - > IP 地址和域名之间的转换

```
https://viewdns.info/reverseip/?host=example.com&t=1
```

### IP converter - - > IP 地址和域名之间的转换

```
https://www.smartconversion.com/unit_conversion/IP_Address_Converter.aspx
```

### Domain History Checker - - > 用于查找特定域名的历史记录

```
https://whoisrequest.com/history/
```

### Check in ThreatCrowd - - > 用于查找特定域名或 IP 地址的恶意软件和其他威胁

```
http://threatcrowd.org/domain.php?domain=example.com
```

### Search in DomainEye - - > 用于查找特定域名的相关信息

```
https://domaineye.com/similar/example.com
```

### Search in bgp ASN - - > 用于查找特定 ASN 的相关信息

```
https://bgp.he.net/search?search%5Bsearch%5D=example.com&commit=Search
```

### Search in asnlookup ASN - - > 用于查找特定 ASN 的相关信息

```
https://asnlookup.com/organization/example.com
```

### Search in grep.app - - > 用于搜索特定的文本内容

```
https://grep.app/search?q=example.com
```

### Source code search engine - - > 用于查找特定代码片段的位置

```
https://publicwww.com/
```

### Test CrossDomain - - > 用于检查网站是否支持跨域请求

```
https://example.com/crossdomain.xml
```

### Security Headers - - > 用于检查网站的安全配置

```
https://securityheaders.com/?q=example.com&followRedirects=on
```

### SSL Server Test - - > 用于检查 SSL 证书的有效性和安全性

```
https://www.ssllabs.com/ssltest/analyze.html?d=example.com
```

### Search in httpstatus - - > 用于查看 HTTP 状态码的含义和描述

```
https://httpstatus.io
```

### DNSBin - - > 用于接收和查看 HTTP 请求的工具

```
https://requestbin.net/
```

### Search in Censys (IPv4)

```
https://censys.io/ipv4?q=example.com
```

### Search in Censys (Domain)

```
https://censys.io/domain?q=example.com
```

### Search in Censys Hosts

```
https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=100&virtual_hosts=EXCLUDE&q=example.com
```

### Search in Censys Certificates

```
https://search.censys.io/certificates?q=example.com
```

### Search in OpenBugBounty

```
https://www.openbugbounty.org/search/?search=example.com
```

### Facebook Certificate Transparency Monitoring (Recon)

```
https://developers.facebook.com/tools/ct/
```

### Find SWF links in the past - - > 用于查找特定域名的 SWF 文件

```
https://web.archive.org/cdx/search?url=example.com/&matchType=domain&collapse=urlkey&output=text&fl=original&filter=urlkey:.*swf&limit=100000&_=1507209148310
```

### Find MIME-SWF links in the past - - > 用于查找特定域名的 SWF 文件

```
https://web.archive.org/cdx/search?url=example.com/&matchType=domain&collapse=urlkey&output=text&fl=original&filter=mimetype:application/x-shockwave-flash&limit=100000&_=1507209148310
```

### WordPress Scan #1

```
https://hackertarget.com/wordpress-security-scan/
```

### WordPress Scan #2

```
https://wprecon.com/
```

### Search WP Config Backup - - > 用于查找特定域名的 WP 配置备份文件

```
http://wwwb-dedup.us.archive.org:8083/cdx/search?url=example.com/&matchType=domain&collapse=digest&output=text&fl=original,timestamp&filter=urlkey:.*wp[-].*&limit=1000000&xx=
```

