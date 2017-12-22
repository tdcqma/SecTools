Readme

1. 脚本使用python3开发
2. 执行顺序为先使用crawler_v2.0.py抓取漏洞信息并保存在本地文件内，然后利用脚本sendmail.sh读取文件内容并发送邮件。
3. 利用linux的计划任务定期执行两个脚本，以达到每天获取漏洞的任务。计划任务类似如下效果：
	# crontab -l
	35 23 * * * python3 /root/crawler/crawler_v2.0.py  # 生成爬虫日志文件
	45 23 * * * /root/crawler/Crawler_SecInfoLog/sendmail.sh # 将生成的爬虫日志文件邮件发送到客户端
