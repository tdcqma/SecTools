#! /usr/bin/env python
# -*- coding:utf-8 -*-
# Author: Tdcqma

'''
    获取漏洞目标站点：绿盟安全漏洞通告

v1.0:
    由于网站结构存在变更的可能性，一旦爬虫爬取的页面发生变化则会影响正则表达式的匹配，导致爬虫失效。为了解决这个问题重新架构该爬虫，新的爬虫将分3个部分，即：
    【1】信息收集：一旦网站结构发生变化只需要更改此部分的正则表达式即可，收集的信息需要保存至一个嵌套列表中。
    【2】信息筛选：即使网站结构发生变化也不需要变更此部分。
    【3】信息发送：即使网站结构发生变化也不需要变更此部分。

v1.1
    添加 "风险级别" 功能到报警信息中，由【CVE 通用漏洞与披露】库中获取对应漏洞的风险级别
v1.2
    添加漏洞总数功能
v1.3
    删除"风险级别"选项，因为http://cve.scap.org.cn/站点故障
    优化代码
v1.4
    使用BeautifulSoup模块优化内容搜索
v1.5
    优化模块2（信息筛选），对信息进行按系统分类显示
v1.6
    优化v1.5部分，对代码部分进行函数化整理
v1.7
    完善待监控的系统，包括tomcat、weblogic、redis、nginx、keepalive、activemq、redhat等
V1.8
    对当日没有检测到漏洞的系统给出无检出漏洞的提示，例如“无新漏洞被发现”
V1.9
    更新邮件发送模块
v2.0 
    更新邮件，添加抄送功能
'''

import urllib.request
import ssl, re
import smtplib, email
import datetime
from bs4 import BeautifulSoup
import traceback, sys
from email.mime.text import MIMEText
from email.header import Header

# ---------------------------------------------
# 【1】信息收集，正则表达匹配网站信息，包括date、title、url等，
#      将所有信息保存至sec_all_list列表中
# ---------------------------------------------
try:
    # 爬虫爬取当天的漏洞告警信息，也可指定如2017-10-09样式的日期格式用于开发过程中的测试
    today = str(datetime.date.today())
    #today = "2017-11-15"

    # 放到linux服务器的时候Crawler_SecInfoLog文件夹需改为绝对路径
    f = open("/root/crawler/Crawler_SecInfoLog/%s_Crawler_SecInfoLog.txt" % today, 'w', encoding='utf-8')

    # 指定爬虫网站的首页链接
    sec_vul_domain = "http://www.nsfocus.net/"

    # 生成字典用于保存漏洞网站的跳转链接
    vul_dict = {}

    # 该变量保存漏洞跳转页面链接：http://www.nsfocus.net/index.php?act=sec_bug
    sec_vul_homepage = ""

    # 收集所有漏洞信息并保存在列表中
    sec_all_list = []

    # 将列表漏洞转换为字符串
    data_str = ""

    # 将需要监控的系统名称添加至该列表即可实现爬虫功能
    system_list = ["Tomcat", "WebLogic", "Redis", "Nginx", "keepalive", "ActiveMQ", "Redhat"]

    # 该变量保存所有指定系统的格式化后的漏洞信息，邮件发送也是基于该变量里保存的漏洞信息
    all_vul_msg = ""

    # 计算漏洞总数
    count = 0


    # 获取相应Response的函数
    def get_response(vul_url):
        request = urllib.request.Request(vul_url)
        # 当尝试访问https开始当站点时，设置全局取消SSL证书验证
        ssl._create_default_https_context = ssl._create_unverified_context
        response = urllib.request.urlopen(request)
        data = response.read().decode('utf-8')
        return data


    # 使用正则匹配的话，如果站点一旦结构发生变化匹配即将失效，爬虫即失效。因此此处借助BeautifulSoup模块，
    # 扫描出全站点url(保存于变量all_url中)，查找"安全漏洞"模块所对应的链接并保存至变量中方便后代码使用。
    data_homepage = get_response(sec_vul_domain)
    soup = BeautifulSoup(data_homepage, features="lxml")
    all_url = soup.find_all(name='a')
    for item in all_url:
        if "安全漏洞" in item:
            # 通过获取标签属性，即使站点结构发生变化也能拿到漏洞页面的链接
            attrs = item.attrs
            vul_dict = attrs.copy()

    # sec_vul_homepage变量用于保存"安全漏洞"的链接
    sec_vul_homepage = vul_dict.get('href')

    # 爬虫运行入口：
    # 因同一天的爆出的漏洞个数如果过多可能要占用几个页面，需指定被扫描网站需要扫描的网页数范围，默认读取10页
    for vul_page in range(15):
        sec_vul_pageNoUrl = sec_vul_homepage + "&type_id=&os=&keyword=&page=%s" % (vul_page + 1)
        data_sec_vul = get_response(sec_vul_pageNoUrl)

        if today in data_sec_vul:
            str_re = "<span>" + today + "</span>.*"
            res = re.findall(str_re, data_sec_vul)
            for item in res:
                data_str += item + '\n'

            sec_vul_soup = BeautifulSoup(data_str, features="lxml")
            tag_a = sec_vul_soup.find_all(name='a')

            for item in tag_a:
                # 生成列表用于收集单独的漏洞信息
                sec_sub_list = []
                # 收集漏洞标题: title
                sec_sub_title = item.string
                sec_sub_list.append(sec_sub_title)

                # 收集漏洞url: sec_sub_url
                item = str(item)
                sub_url = re.findall("vulndb/\d+", item)
                sec_sub_url = sec_vul_domain + sub_url[0]
                sec_sub_list.append(sec_sub_url)

                # 收集漏洞受影响的版本: aff_ver
                # 格式化输出
                data_sec_vul_cve = get_response(sec_sub_url)
                affected_version = re.findall("<blockquote>.*</blockquote>", data_sec_vul_cve, re.S)
                affected_version = str(affected_version[0][12:-13])
                affected_version = affected_version.replace("<br />", "")
                affected_version = affected_version.replace("&gt;", ">")
                affected_version = affected_version.replace("&lt;", "<")
                aff_ver = affected_version.replace("</blockquote><b>不受影响系统：</b><blockquote>", "\n不受影响版本：\n")
                sec_sub_list.append(aff_ver)
                if sec_sub_list not in sec_all_list:
                    sec_all_list.append(sec_sub_list)

    # ---------------------------------------------
    # 【2】信息筛选
    # ---------------------------------------------

    # 各系统漏洞在筛选后最终会保存至各自msg_***变量中，
    # >>>添加新监控系统时需相应添加以下记录<<<
    msg_webLogic = ">>> WebLogic安全通告\n"
    msg_tomcat = "\n>>> Tomcat安全通告\n"
    msg_redis = "\n>>> Redis安全通告\n"
    msg_nginx = "\n>>> Nginx安全通告\n"
    msg_keepalive = "\n>>> Keepalive安全通告\n"
    msg_activemq = "\n>>> ActiveMQ安全通告\n"
    msg_redhat = "\n>>> RedHat安全通告\n"


    # 调用sub_sec_info方法，将漏洞信息格式化输出
    def sub_sec_info():
        global count
        count += 1
        sec_info = "\n漏洞名称：" + line[0] \
                   + "\n漏洞链接：" + line[1] \
                   + "\n受影响的系统：\n" + line[2] + '\n'
        return sec_info


    # 调用get_sec_info函数，将目标系统或应用名称作为参数传入，即可获取相关爬虫告警信息
    def get_sec_info(sys):
        # sys = sys.capitalize() # 系统关键字首字母大写
        # >>>添加新监控系统时需相应添加以下记录<<<
        global msg_webLogic
        global msg_tomcat
        global msg_redis
        global msg_nginx
        global msg_keepalive
        global msg_activemq
        global msg_redhat

        # >>>添加新监控系统时需相应添加以下elif记录<<<
        if sys in line[0]:
            if "WebLogic" in sys:
                msg_webLogic += sub_sec_info()
            elif "Tomcat" in sys:
                msg_tomcat += sub_sec_info()
            elif "Redis" in sys:
                msg_redis += sub_sec_info()
            elif "Nginx" in sys:
                msg_nginx += sub_sec_info()
            elif "keepalive" in sys:
                msg_keepalive += sub_sec_info()
            elif "ActiveMQ" in sys:
                msg_activemq += sub_sec_info()
            elif "Redhat" in sys:
                msg_redhat += sub_sec_info()


    # 漏洞信息筛选入口函数
    for line in sec_all_list:
        for sys in system_list:
            get_sec_info(sys)


    # >>>添加新监控系统时需相应添加以下记录<<<

    # 若吴新漏洞被发现则在漏洞标题后面添加“本日无新漏洞被发现”
    def len_msg(msg_sys):
        if len(msg_sys) < 30:
            msg_sys += '    今日无新漏洞发现\n'
        return msg_sys


    all_vul_msg += len_msg(msg_webLogic)
    all_vul_msg += len_msg(msg_tomcat)
    all_vul_msg += len_msg(msg_redis)
    all_vul_msg += len_msg(msg_nginx)
    all_vul_msg += len_msg(msg_keepalive)
    all_vul_msg += len_msg(msg_activemq)
    all_vul_msg += len_msg(msg_redhat)

    # 在内容结尾处添加爬虫检测出的漏洞总数
    all_vul_msg += "\n漏洞总数: " + '['+str(count)+']'

except Exception as e:
    t, v, tb = sys.exc_info()
    formatted_lines = traceback.format_exc().splitlines()

    # 获取详细堆栈信息
    dz_msg = ''''''
    for line_f in formatted_lines:
        dz_msg += line_f + '\n'

    if 'urllib.error.URLError' in str(t):
        all_vul_msg += '【爬虫故障信息】\n\t' + '站点域名或跳转链接或网络可能产生错误，请立刻确认!!!\n\t' * 2
        all_vul_msg += '站点域名或跳转链接或网络可能产生错误，请立刻确认!!!\n'

    all_vul_msg += '\n【详细异常信息】\n'
    all_vul_msg += '\t异常类型：' + str(t) + \
                   '\n\t异常实例：' + str(v) + \
                   '\n\n【traceback信息:】\n\t' + dz_msg
    all_vul_msg += '\n\n【主意事项】 \n\t当网络通讯未出现异常的时候可以收到此类异常告警邮件，但是当爬虫服务器网络\n' \
                   '\t出现故障的时候你可能无法接收邮件告警，此时定位问题可以登录爬虫服务器（192.168.22.214）：\n' \
                   '\t查看/root/crawler/Crawler_SecInfoLog/下的日志文件来排查问题！'
finally:
    # 为防止数据丢失，同时将筛选后的爬虫信息写入文本f中，f指向secInfo-lvmeng.txt文档。
    f.writelines(all_vul_msg) 
