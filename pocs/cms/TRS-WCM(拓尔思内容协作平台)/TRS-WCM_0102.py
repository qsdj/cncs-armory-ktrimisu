# coding: utf-8
from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'TRS-WCM_0102'  # 平台漏洞编号，留空
    name = 'TRSWCM 5.2 /wcm/services/ 文件上传漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-07-29'  # 漏洞公布时间
    desc = '''
        TRS Web Content Management( TRS WCM ), 是-套完全基于Java和浏览器技术的网络内容管理软件。
        TRSWCM的Web Service提供了向服务器写入文件的方式，可以直接写jsp文件获取webshell。
    '''  # 漏洞描述
    ref = 'http://www.wooyun.org/bugs/wooyun-2015-092138'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'TRS-WCM(拓尔思内容协作平台)'  # 漏洞应用名称
    product_version = '5.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3ab334d5-def0-44e1-ae93-71be6e75a303'  # 平台 POC 编号，留空
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
            url = self.target
            payload = '/wcm/services/trs:templateservicefacade?wsdl'
            verify_url = url + payload
            req = requests.get(verify_url)
            if req.status_code == 200 and 'writeFile' in req.text and 'writeSpecFile' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
