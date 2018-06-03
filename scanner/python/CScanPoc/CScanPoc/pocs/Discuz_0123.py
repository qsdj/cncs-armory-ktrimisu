# coding: utf-8
import md5
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Discuz_0123' # 平台漏洞编号，留空
    name = 'Discuz x3.0 /static/image/common/mp3player.swf 跨站脚本漏洞' # 漏洞名称
    level = VulnLevel.LOW # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2014-09-30'  # 漏洞公布时间
    desc = '''
    Discuz X3.0 static/image/common/mp3player.swf文件存在FlashXss漏洞。
    ''' # 漏洞描述
    ref = 'http://www.ipuman.com/pm6/138/'# 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz'  # 漏洞应用名称
    product_version = '3.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd9228e09-a090-48e8-9ef1-558744ac234f' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            flash_md5 = "f73b6405a9bb7a06ecca93bfc89f8d81"
            file_path = "/static/image/common/mp3player.swf"
            verify_url = self.target + file_path
            request = urllib2.Request(verify_url)
            response = urllib2.urlopen(request)
            content = response.read()
            md5_value = md5.new(content).hexdigest()
            if md5_value in flash_md5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()