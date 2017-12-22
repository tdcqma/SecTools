#！/bin/bash

cat /root/crawler/Crawler_SecInfoLog/"`date +%F`_Crawler_SecInfoLog.txt" | mail -s "爬虫预警(`date +%F`)" receive_mail@163.com
