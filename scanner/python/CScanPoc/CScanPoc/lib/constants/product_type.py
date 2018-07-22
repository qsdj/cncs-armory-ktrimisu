# coding: utf-8

import logging
from pypinyin import Style, pinyin
from CScanPoc.lib.core.enums import ProductType

_warned = {}


def get_product_info(name, log_unknown=True):
    '''获取指定名字的产品/组件信息

    @param name 为 None 时，返回 None
    '''
    if name is None or name.strip() == '':
        return None
    result = {}
    if name in PRODUCT_INFO:
        result = PRODUCT_INFO[name]
    else:
        result = {"type": ProductType.others}

    if log_unknown and name not in _warned:
        _warned[name] = True
        try:
            logging.warn(
                u'组件类型信息未定义: {} 可以在 CScanPoc.lib.constatants.product_type.PRODUCT_INFO 中定义'.format(name))
        except:
            logging.warn(name)
    result['name_pinyin_first'] = __get_pinyin_first_letter(name)
    return result


def __get_pinyin_first_letter(name):
    try:
        # https://github.com/mozillazg/python-pinyin
        return pinyin(name, style=Style.INITIALS, strict=False)[0][0][0].lower()
    except:
        return 'a'


PRODUCT_INFO = {
    "ExtMail": {
        "type": ProductType.cms,
        "producer": "广州领立斯网络科技有限公司",
        "desc": "Extmail 是一个以perl语言编写，面向大容量/ISP级应用，免费的高性能Webmail软件，主要包括ExtMail、Extman两个部分的程序套件。ExtMail套件用于提供从浏览器中登录、使用邮件系统的Web操作界面，而Extman套件用于提供从浏览器中管理邮件系统的Web操作界面。它以GPL版权释出，设计初衷是希望设计一个适应当前高速发展的IT应用环境，满足用户多变的需求，能快速进行开发、改进和升级，适应能力强的webmail系统。"
    },
    "XpShop(新普)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "舜网": {
        "type": ProductType.others,
        "producer": "山东舜网传媒股份有限公司",
        "desc": "舜网是由济南日报报业集团主办,是国务院新闻办公室批准的济南市唯一新闻网站、山东省重点新闻网 站,是济南最大的综合信息网络门户。"
    },
    "MonstraCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "Monstra is a content management system (CMS) written for server environments where a database is just too much to handle and/or is inaccessible."
    },
    "Info_Git(Git源码泄露)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Pearl For Mambo": {
        "type": ProductType.others,
        "producer": None,
        "desc": "Mambo是免费的功能强大的开放源码内容管理系统，Pearl For Mambo是可以无缝的集成于Mambo的一个组件。"
    },
    "fcgi": {
        "type": ProductType.middleware,
        "producer": "FastCGI",
        "desc": "CGI全称是“通用网关接口”(Common Gateway Interface)，HTTP服务器与你的或其它机器上的程序进行“交谈”的一种工具，其程序一般运行在网络服务器上。 CGI可以用任何一种语言编写，只要这种语言具有标准输入、输出和环境变量。如php,perl,tcl等。"
    },
    "3g门户网": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Git": {
        "type": ProductType.others,
        "producer": "Git",
        "desc": "Git(读音为/gɪt/。)是一个开源的分布式版本控制系统，可以有效、高速的处理从很小到非常大的项目版本管理。Git 是 Linus Torvalds 为了帮助管理 Linux 内核开发而开发的一个开放源码的版本控制软件。"
    },
    "KISGB": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "泰合佳通": {
        "type": ProductType.others,
        "producer": "北京泰合佳通信息技术有限公司",
        "desc": "泰合佳通内网站点。"
    },
    "Modernbill": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": None
    },
    "DichanCMS": {
        "type": ProductType.cms,
        "producer": "新浪",
        "desc": "新浪地产CMS站点。"
    },
    "PHPMyAdmin": {
        "type": ProductType.cms,
        "producer": "phpMyAdmin",
        "desc": "phpMyAdmin 是一个以PHP为基础，以Web-Base方式架构在网站主机上的MySQL的数据库管理工具，让管理者可用Web接口管理MySQL数据库。借由此Web接口可以成为一个简易方式输入繁杂SQL语法的较佳途径，尤其要处理大量资料的汇入及汇出更为方便。其中一个更大的优势在于由于phpMyAdmin跟其他PHP程式一样在网页服务器上执行，但是您可以在任何地方使用这些程式产生的HTML页面，也就是于远端管理MySQL数据库，方便的建立、修改、删除数据库及资料表。也可借由phpMyAdmin建立常用的php语法，方便编写网页时所需要的sql语法正确性。"
    },
    "北京实易时代": {
        "type": ProductType.others,
        "producer": "北京实易时代",
        "desc": "实易DNS管理系统"
    },
    "WeCenter": {
        "type": ProductType.cms,
        "producer": "深圳市微客互动有限公司",
        "desc": "Wecenter(微中心系统软件)是一款由深圳市微客互动有限公司开发的具有完全自主知识产权的开源软件."
    },
    "Yoka": {
        "type": ProductType.others,
        "producer": None,
        "desc": "YOKA时尚网是服务于高收入群体的时尚生活门户,时尚网站.专注提供时尚奢侈品资讯报道,品牌动态,购物交流等服务;同时也是时尚人士,明星生活交流的主题社区。"
    },
    "游族网络": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Apache": {
        "type": ProductType.middleware,
        "producer": "Apache软件基金会",
        "desc": "Apache是世界使用排名第一的Web服务器软件。它可以运行在几乎所有广泛使用的计算机平台上，由于其跨平台和安全性被广泛使用，是最流行的Web服务器端软件之一。它快速、可靠并且可通过简单的API扩充，将Perl/Python等解释器编译到服务器中。"
    },
    "Shmtu": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "51job": {
        "type": ProductType.others,
        "producer": "前程无忧",
        "desc": "前程无忧”(即 51job) 是中国具有广泛影响力的人力资源服务供应商，在美国上市的中国人力资源服务企业。它运用了网络媒体及先进的移动端信息技术，加上经验丰富的专业顾问队伍，提供包括招聘猎头、培训测评和人事外包在内的全方位专业人力资源服务，现在全国25个城市设有服务机构，是国内领先的专业人力资源服务机构。"
    },
    "Airshop": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "phpMBBCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "PHP MBB, sebuah CMS sederhana cocok digunakan untuk keperluan misalnya, pembangunan web sekolah, toko dan keperluan lainnya secara universal."
    },
    "AKCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "AKCMS一个轻量级的PHP的小型CMS(内容管理系统）！灵活，可靠，功能实用，支持MySQL、SQLite，支持整站HTML静态化，采集功能，适合做几乎所有的WEB1.0网站：文章站、网址站、门户站、书库站、下载站、音乐站等。"
    },
    "Flash": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": None
    },
    "青果教务系统": {
        "type": ProductType.cms,
        "producer": "湖南青果软件有限公司",
        "desc": None
    },
    "ThinkOX": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "2015 年 1 月 28 日 ThinkOX 正式更名为 OpenSNS，意思是基于OpenCenter的社交程序。"
    },
    "Django": {
        "type": ProductType.cms,
        "producer": "Django软件基金会",
        "desc": "Django是一个开放源代码的Web应用框架，由Python写成。采用了MVC的框架模式，即模型M，视图V和控制器C。它最初是被开发来用于管理劳伦斯出版集团旗下的一些以新闻内容为主的网站的，即是CMS（内容管理系统）软件。并于2005年7月在BSD许可证下发布。这套框架是以比利时的吉普赛爵士吉他手Django Reinhardt来命名的。"
    },
    "乐知行教务系统": {
        "type": ProductType.cms,
        "producer": "讯飞乐知行",
        "desc": "乐知行教学系统。"
    },
    "远为应用安全网关": {
        "type": ProductType.device,
        "producer": "北京远为软件有限公司",
        "desc": "远为应用安全网关通过反向代理的方式将业务服务保护在网关之后，并通过HTTPS加密通道、多种强认证、双因素认证、黑名单等技术来提高交互的安全性。在互联网访问内网的场景中，针对HTTP协议下的各种类型的服务访问，SPG可以替代VPN，且支持集群部署应对高并发，实现安全便捷的访问体验，为企业降本增效。"
    },
    "Xxzcity": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Sitestar": {
        "type": ProductType.cms,
        "producer": "上海美橙科技信息发展有限公司",
        "desc": "企业智能建站系统—建站之星SiteStar系统该款建站软件完全从网络营销角度开发，结合了企业对网站的内容结构、应用功能、页面呈现等方面的市场需求。"
    },
    "安踏": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "ThinkOK": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "YouYaX": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "YouYaX是用PHP语言编写的一套通用论坛系统。秉承简洁实用的设计原则，将传统论坛中一些复杂臃肿的部分统统去掉，保留论坛交流的本质核心，拥有自己独特的原创风格和特性，并且在不断优化和改进。"
    },
    "XR网关平台": {
        "type": ProductType.device,
        "producer": None,
        "desc": None
    },
    "U-Mail": {
        "type": ProductType.middleware,
        "producer": "深圳市福洽科技有限公司",
        "desc": "U-Mail专家级邮件系统是福洽科技最新推出的第四代企业邮局系统。该产品依托福洽科技在信息领域中领先的技术与完善的服务，专门针对互联网信息技术的特点，综合多行业多领域不同类型企业自身信息管理发展的特点，采用与国际先进技术接轨的专业系统和设备，将先进的网络信息技术与企业自身的信息管理需要完美的结合起来。"
    },
    "Bohoog": {
        "type": ProductType.others,
        "producer": "贵州博虹科技有限公司",
        "desc": "贵州博虹科技政府建站程序"
    },
    "GeverCMS": {
        "type": ProductType.cms,
        "producer": "广东金宇恒软件科技有限公司",
        "desc": "金宇恒内容管理系统。"
    },
    "Shopin": {
        "type": ProductType.cms,
        "producer": "北京市上品商业发展有限责任公司",
        "desc": "上品折扣网官方站点。"
    },
    "Zookeeper": {
        "type": ProductType.middleware,
        "producer": "Apache Software Foundation",
        "desc": "ZooKeeper是一个分布式的，开放源码的分布式应用程序协调服务，是Google的Chubby一个开源的实现，是Hadoop和Hbase的重要组件。它是一个为分布式应用提供一致性服务的软件，提供的功能包括：配置维护、域名服务、分布式同步、组服务等。ZooKeeper的目标就是封装好复杂易出错的关键服务，将简单易用的接口和性能高效、功能稳定的系统提供给用户。\nZooKeeper包含一个简单的原语集，提供Java和C的接口。"
    },
    "XForwardedFor": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "55tuan(窝窝团)": {
        "type": ProductType.others,
        "producer": "北京窝窝团信息技术有限公司",
        "desc": "窝窝团是窝窝商城旗下子品牌,成立于2010年3月15日,是国内的团购网站。 "
    },
    "华创": {
        "type": ProductType.others,
        "producer": "北京华夏创新科技有限公司",
        "desc": "华创网络设备。"
    },
    "Mallbuilder": {
        "type": ProductType.cms,
        "producer": "远丰集团",
        "desc": "MallBuilder是一款基于PHP+MYSQL的多用户网上商城解决方案，利用MallBuilder可以快速建立一个功能强大的类似京东商城、天猫商城、1号店商城的网上商城，或企业化、行业化、本地化和垂直化的多用户商城，MallBuilder是B2Bbuilder的姊妹篇，她除了延续B2Bbuilder的众多优点之外，还增加了许多新功能，使操作更加简单，功能更加完善，性能更加稳定的多用户商城建设系统。"
    },
    "ECGAP电子政务系统": {
        "type": ProductType.cms,
        "producer": "浪潮集团有限公司",
        "desc": "浪潮政务审批平台ECGAP 基于对行政审批信息化的深刻理解和把握，在平台化理念指导下，浪潮着力研发出了政务审批平台（ECGAP），满足政府行政审批的需要，用来解决政府 G2G、G2B、G2C、G2E等各种应用的综合解决方案。它满足政府行政审批的各种应用模式和管理模式。产品概述 浪潮行政审批电子监察系统 浪潮行政审批电子监察系统围绕行政审批业务，从政务公开、办事过程、收费管理、投诉举报等方面进行事前、事中、事后全过程监控。"
    },
    "Newvane(新风向在线考试系统)": {
        "type": ProductType.cms,
        "producer": "深圳市新风向科技有限公司",
        "desc": "新风向科技致力于开发、引进、整合、传播各类优秀教育培训资源及相关软件系统技术，并配以卓越的技术力量和专业的顾问式服务，帮助客户建立一套快速有效的在线培训和考试模式。"
    },
    "新浪": {
        "type": ProductType.others,
        "producer": "新浪公司",
        "desc": "新浪是一家网络公司的名称，成立于1998年12月，由王志东创立，现任董事长为：曹国伟，服务大中华地区与海外华人，新浪拥有多家地区性网站。"
    },
    "ASPCMS": {
        "type": ProductType.cms,
        "producer": "上谷网络",
        "desc": "ASPCMS是由上谷网络开发的全新内核的开源企业建站系统，能够胜任企业多种建站需求，并且支持模版自定义、支持扩展插件等等，能够在短时间内完成企业建站。"
    },
    "Gxwssb": {
        "type": ProductType.cms,
        "producer": "天津神州浩天科技有限公司",
        "desc": "Gxwssb，大学网上自助平台，该系统目前大部分运用在高校内网。"
    },
    "V5shop": {
        "type": ProductType.cms,
        "producer": "上海威博",
        "desc": "V5Shop网店系统是上海威博旗下一款B to C网上开店软件产品，适合中小型企业及个人快速构建个性化网上商店。上海威博创始于2002年，是中国最具技术实力、国内市场占有率最高的电子商务系统提供商之一。旗下拥有V5SHOP网店系统个人版、V5SHOP企业级电子商务系统标准版、V5SHOP企业级电子商务系统双核版、V5SHOP企业级电子商务系统全程版、V5MALL商城系统、V5SHOP多国语言系统、V5SHOP联盟系统以及众多网店辅助工具。"
    },
    "PHP168": {
        "type": ProductType.cms,
        "producer": "广州国微软件科技有限公司",
        "desc": "PHP168整站是PHP的建站系统，代码全部开源，是国内知名的开源软件提供商；提供核心+模块+插件的模式；任何应用均可在线体验。"
    },
    "聚美优品": {
        "type": ProductType.others,
        "producer": "聚美优品",
        "desc": None
    },
    "Shop7z": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "Shop7z网上购物系统是国内优秀的网上开店软件，模板新颖独特，功能强大，自主知识产权国家认证，数万用户网上开店首选，可以快速建立自己的网上商城。"
    },
    "國立中央大學": {
        "type": ProductType.others,
        "producer": "台湾中央大学",
        "desc": "台湾中央大学官方站点。"
    },
    "Jinti": {
        "type": ProductType.others,
        "producer": "今题网",
        "desc": "今题网官方站点。"
    },
    "Duowan": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "巨人网络": {
        "type": ProductType.others,
        "producer": "巨人网络",
        "desc": "巨人网络官方站点。"
    },
    "ApacheJamesServer": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "PigCMS(小猪CMS)": {
        "type": ProductType.cms,
        "producer": "合肥彼岸互联信息技术有限公司",
        "desc": "2013年作为微信生态下最早的一批开发商，小猪CMS是中国较早的微信营销CMS。"
    },
    "EmpireCMS": {
        "type": ProductType.cms,
        "producer": "漳州市芗城帝兴软件开发有限公司",
        "desc": "帝国软件是一家专注于网络软件开发的科技公司，其主营产品“帝国网站管理系统(EmpireCMS)”是目前国内应用最广泛的CMS程序。通过多年的不断创新与完善，使系统集安全、强大、稳定、灵活于一身。 目前EmpireCMS程序已经广泛应用在国内数十万家网站，覆盖国内上千万上网人群，并经过上千家知名网站的严格检测，被称为国内最稳定的CMS系统。 帝国软件将致力于为中国网站提供最完善的建站解决方案为已任，打造国内最好的CMS程序。"
    },
    "Destoon": {
        "type": ProductType.cms,
        "producer": "西安嘉客信息科技有限责任公司",
        "desc": "DESTOON B2B网站管理系统是一套基于PHP+MySQL的开源B2B电子商务行业门户网站解决方案。"
    },
    "星网锐捷语音网关": {
        "type": ProductType.device,
        "producer": None,
        "desc": None
    },
    "NetrunVPN": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": None
    },
    "PCMan FTP Server": {
        "type": ProductType.middleware,
        "producer": "SourceForge",
        "desc": "PCMan's FTP Server是简单易于的基础FTP服务器。"
    },
    "Emlog": {
        "type": ProductType.cms,
        "producer": "Emlog",
        "desc": "emlog 是 \"Every Memory Log\" 的简称，意即：点滴记忆。它是一款基于PHP语言和MySQL数据库的开源、免费、功能强大的个人或多人联合撰写的博客系统(blog)。致力于提供快速、稳定，且在使用上又极其简单、舒适的博客服务。用户可以在支持PHP语言 和MySQL数据库的服务器上建立自己的Blog。emlog的功能非常强大，模板、插件众多，易于扩充功能，简洁而不简单。安装和使用都非常方便。目前 emlog 正在受到越来越多的广大用户的青睐。"
    },
    "万鹏通用教育类门户系统": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Sangfor(深信服)": {
        "type": ProductType.others,
        "producer": "深信服",
        "desc": "深信服网络设备。"
    },
    "EWEBS": {
        "type": ProductType.others,
        "producer": "北京汉邦极通科技有限公司",
        "desc": "在平媒和网络媒体都可以见到了，EWEBS从这个词的构成来看是e+web+s构成的，大体一想就是和IT有关的，e代表的IE浏览器，web强调的是互联网，可以引射出次产品的作用是一种通过浏览器实现B/S的东西。"
    },
    "FT中文网": {
        "type": ProductType.others,
        "producer": "FT中文网",
        "desc": "FT中文网官方站点。"
    },
    "网域高校CMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "江南科友堡垒机": {
        "type": ProductType.device,
        "producer": "江南科友",
        "desc": "江南科友堡垒机。"
    },
    "乐语客服系统": {
        "type": ProductType.cms,
        "producer": "多友科技（北京）有限公司",
        "desc": "乐语OMS是一款整合多终端的即时在线客服系统，支持千万级并发，让企业迅速捕获有效客户信息。同时整合CRM客户管理、数据分析、手机站群营销等功能，实现从流量到客户到成单再到数据分析的全流程管理，是企业构建网络营销运营系统必备的软件。"
    },
    "WebUI": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": None
    },
    "Apache ActiveMQ": {
        "type": ProductType.middleware,
        "producer": "Apache软件基金会",
        "desc": "Apache ActiveMQ是一款开源消息总线，支持JMS1.1和J2EE 1.4规范的JMS Provider实现。"
    },
    "烟台吉安电子": {
        "type": ProductType.others,
        "producer": "烟台吉安电子科技有限公司",
        "desc": "烟台吉安电子科技有限公司是国内测控行业的领军公司，主营温度巡检仪,机房环境监控,测温仪,机房监控,陀螺测斜,机房环境动力监控,彩票信息管理软件等，公司成立于2002年7月。是烟台市科委认证的以新技术研发、产品设计、推广、生产为主的高新企业，总部设于烟台市莱山区高新技术核心区。"
    },
    "Linksys": {
        "type": ProductType.device,
        "producer": "Cisco",
        "desc": "Linksys是思科系统一个销售家用与小型业务用网络产品的部门。Linksys最初于1988年创立，2003年被思科收购。尽管Linksys最知名的是其宽带与无线路由器，但亦有生产以太网交换与VoIP装置以及多种其他产品。"
    },
    "rockOA": {
        "type": ProductType.cms,
        "producer": "信呼",
        "desc": "为企业构建一个基于互联网的企业管理平台, 对企业中沟通与互动，协作与管理的全方位整合，并且免费开源系统，二次开发更快捷，即时推送审批，掌上APP手机办公。"
    },
    "HumHub": {
        "type": ProductType.others,
        "producer": "HumHub",
        "desc": "humhub是一个PHP写成的灵活的开源社交网络应用。是一个免费的社会网络软件和框架。它重量轻，功能强大，配备了一个友好的用户界面。humhub与您可以创建自己的定制的社会网络，社会网络或社会的巨大的企业应用，真正适合你的需要。强大的，灵活的和100%开放源代码，humhub是快速，容易和最预算友好的方式来构建自己的社会性软件。"
    },
    "ThinkSAAS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "ThinkSAAS开源社区基于PHP+MySQL开发完成，运行于Linux 平台和Windows平台，完美支持Apache和Nginx运行环境。"
    },
    "CouchDB": {
        "type": ProductType.database,
        "producer": "Apache软件基金会",
        "desc": "Apache CouchDB 是一个开源数据库，专注于易用性和成为\"完全拥抱web的数据库\"。它是一个使用JSON作为存储格式，JavaScript作为查询语言，MapReduce和HTTP作为API的NoSQL数据库。其中一个显著的功能就是多主复制。CouchDB 的第一个版本发布在2005年，在2008年成为了Apache的项目。"
    },
    "CCTV": {
        "type": ProductType.others,
        "producer": "Cctv",
        "desc": "CCTV子站本地文件包含。"
    },
    "SiteFactoryCMS": {
        "type": ProductType.cms,
        "producer": "广东动易软件股份有限公司",
        "desc": "动易SiteFactory内容管理系统是业界首款基于微软.NET2.0平台，采用ASP.NET 2.0进行分层开发的内容管理系统（Content Management System）。"
    },
    "AbsolutEngine": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "Absolut Engine是一个新闻发布系统。"
    },
    "Apache Tomcat": {
        "type": ProductType.middleware,
        "producer": "Apache软件基金会",
        "desc": "Apache Tomcat是一款开放源码的JSP应用服务器程序。"
    },
    "GlassFish": {
        "type": ProductType.others,
        "producer": "GlassFish",
        "desc": "GlassFish 是一款强健的商业兼容应用服务器，达到产品级质量，可免费用于开发、部署和重新分发。开发者可以免费获得源代码，还可以对代码进行更改。"
    },
    "SmartOA": {
        "type": ProductType.cms,
        "producer": " 广州智雄软件有限公司",
        "desc": "智明协同oa系统提供专业的oa自定义平台系统(SmartOA),能够快速根据企业需求打造随需而变的个性化oa、OA系统、OA软件、oa办公系统、oa办公软件,协同oa办公平台系统软件。"
    },
    "Cyberwisdom(汇思软件)": {
        "type": ProductType.cms,
        "producer": "汇思软件（上海）有限公司",
        "desc": "提供全面的e-learning解决方案，汇思软件所提供的解决方案主要包括e-Learning学习管理平台、在线学习内容和e-Learning相关的咨询服务三大模块。"
    },
    "批改网": {
        "type": ProductType.others,
        "producer": "北京词网科技有限公司",
        "desc": "批改网基于语料库和云计算技术提供英语作文自动在线批改服务;能及时给出作文的分数、评语以及按句点评,能够提高老师批改英语作文的工作效率,提高学生的英语写作能力。"
    },
    "IWMS": {
        "type": ProductType.cms,
        "producer": "上海百胜软件有限公司",
        "desc": "iwms是国内最早的asp.net新闻系统之一，主要功能有：网页自动采集、防采集、静态生成、图片/文件防盗链、图片/脚本gzip压缩、内置讨论区/广告投放功能、会员付款阅读内容。"
    },
    "Hispider(海蜘蛛)": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": None
    },
    "猫扑OA": {
        "type": ProductType.cms,
        "producer": "重庆猫扑网络科技有限公司",
        "desc": "猫扑OA移动云办公系统，采用行业领先的云计算技术，基于传统互联网和移动互联网，创新云服务+云终端的应用模式， 为企业用户版提供一账号管理聚合应用服务。"
    },
    "Open(奥鹏)": {
        "type": ProductType.cms,
        "producer": "北京奥鹏远程教育中心有限公司",
        "desc": "奥鹏远程教育中心。"
    },
    "FCKeditor": {
        "type": ProductType.others,
        "producer": "CKSource",
        "desc": "FCKeditor是一个专门使用在网页上属于开放源代码的所见即所得文字编辑器。它志于轻量化，不需要太复杂的安装步骤即可使用。它可和PHP、 JavaScript、ASP、ASP.NET、ColdFusion、Java、以及ABAP等不同的编程语言相结合。“FCKeditor”名称中的 “FCK” 是这个编辑器的作者的名字Frederico Caldeira Knabben的缩写。FCKeditor 相容于绝大部分的网页浏览器，像是 : Internet Explorer 5.5+ (Windows)、Mozilla Firefox 1.0+、Mozilla 1.3+ 和 Netscape 7+。在未来的版本也将会加入对 Opera 的支援。"
    },
    "百合网": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "ShopEx": {
        "type": ProductType.cms,
        "producer": "上海派浓网络科技有限公司",
        "desc": "Shopex是国内市场占有率最高的网店软件。网上商店平台软件系统又称网店管理系统、网店程序、网上购物系统、在线购物系统。"
    },
    "Info_webinf": {
        "type": ProductType.others,
        "producer": None,
        "desc": " WEB-INF是Java的Web应用的安全目录。"
    },
    "LBCMS": {
        "type": ProductType.cms,
        "producer": "贵州狼邦科技有限公司",
        "desc": "狼邦内容管理系统。"
    },
    "麦当劳": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "dotWidgetCMS": {
        "type": ProductType.cms,
        "producer": "dot Widget",
        "desc": "dotWidget CMS是基于Web的内容管理系统。"
    },
    "Alstom(阿尔斯通)": {
        "type": ProductType.others,
        "producer": "法国阿尔斯通公司",
        "desc": "阿尔斯通公司（原名通用电气阿尔斯通）是为全球基础设施和工业市场提供部件、系统和服务的主要供应商之一。公司通过能源、输配电、运输、工业设备、船舶设备和工程承包六大业务进行运作。"
    },
    "BookingeCMS": {
        "type": ProductType.cms,
        "producer": "珠海中新信息科技有限公司 ",
        "desc": "预订易酒店预订网站管理系统。"
    },
    "Zhihu": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "DedeCMS(织梦CMS)": {
        "type": ProductType.cms,
        "producer": "上海卓卓网络科技有限公司",
        "desc": "DedeCms 基于PHP+MySQL的技术开发，支持Windows、Linux、Unix等多种服务器平台，从2004年开始发布第一个版本开始，至今已经发布了五个大版本。DedeCms以简单、健壮、灵活、开源几大特点占领了国内CMS的大部份市场，目前已经有超过二十万个站点正在使用DedeCms或居于 DedeCms核心，是目前国内应用最广泛的php类CMS系统。"
    },
    "7Stars(深圳北斗星)": {
        "type": ProductType.others,
        "producer": "深圳市北斗星科技有限公司",
        "desc": "公司经营范围包括电子产品、通讯产品、计算机软硬件、网络产品的技术开发与销售等。"
    },
    "IBM": {
        "type": ProductType.others,
        "producer": "IBM",
        "desc": "IBM官方站点。"
    },
    "53KF": {
        "type": ProductType.cms,
        "producer": "快服科技有限公司",
        "desc": "53KF企业在线是国内使用用户最多的SAAS软件运营平台之一，由快服科技投资创办，致力于成就国内最大的企业云计算服务提供商，专业为企业提供全方位在线软件快速应用服务。"
    },
    "Yunduan": {
        "type": ProductType.others,
        "producer": None,
        "desc": "云端是一款采用应用程序虚拟化技术（Application Virtualization）的软件平台，集软件搜索、下载、使用、管理、备份等多种功能为一体。通过该平台，各类常用软件都能够在独立的虚拟化环境中被封装起来，从而使应用软件不会与系统产生耦合，达到绿色使用软件的目的。"
    },
    "Sinopharm": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "中华信鸽网": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "DayuCMS": {
        "type": ProductType.cms,
        "producer": "DayuCMS",
        "desc": "DayuCMS是一款免费，开源，灵活，简单的CMS系统。"
    },
    "FlashChat": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Diyou(帝友借贷系统)": {
        "type": ProductType.others,
        "producer": " 厦门帝网信息科技有限公司",
        "desc": "公司以“帝友”系统为主的P2P网贷平台开发为主营业务，凭借自身的行业知识和技术经验及客户资源，直接向平台商提供网贷平台优化、建设和开发等业务。"
    },
    "Zhujia360": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "DiliCMS": {
        "type": ProductType.cms,
        "producer": "DiliCMS",
        "desc": "DiliCMS，一个基于CodeIgniter的快速开发内容管理系统。"
    },
    "民安保险": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "中国邮政": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Info_SVN": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "StaMPi": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "金山软件": {
        "type": ProductType.others,
        "producer": "金山",
        "desc": "金山软件。"
    },
    "Ceairgroup(东方航空)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "MyBB": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "MyBB是一款流行的Web论坛程序。"
    },
    "天融信负载均衡系统": {
        "type": ProductType.device,
        "producer": "天融信",
        "desc": "天融信负载均衡系统(TopApp-NLB)是一款融合了智能带宽控制功能的链路及服务器负载均衡产品。通过对网络出口链路和服务器资源的优化调度，TopApp负载均衡系统让大规模的应用部署轻松实现，同时达至最稳定的运行效果，最高的资源利用率，最佳的应用性能和用户体验。大量的企事业单位通过TopApp负载均衡系统顺利实现了应用部署，满足了信息化发展的需求，并极大地提升了工作效率。"
    },
    "奇点网": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Angelo-emlak": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "福建网龙": {
        "type": ProductType.others,
        "producer": "网龙网络公司",
        "desc": "福建网龙数据平台。"
    },
    "Insky CMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "Adidas": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "BEESCMS": {
        "type": ProductType.cms,
        "producer": "BEESCMS",
        "desc": "BEESCMS企业网站管理系统是一款PHP+MYSQL的多语言系统，内容模块易扩展，模板风格多样化，模板制作简单功能强大，专业SEO优化，后台操作方便，完全可以满足企业网站、外贸网站、事业单位、教育机构、个人网站使用。"
    },
    "CSDJCMS(程氏舞曲管理系统)": {
        "type": ProductType.cms,
        "producer": "程氏舞曲管理系统",
        "desc": "程氏舞曲系统是一款唱歌网站，支持目前全部主流网络播放器支持MP3、WMA、webplayer9、土豆、优酷、FLV、Swf、QQ、搜狐、六间房、56、sina、rm、Wmv等主流播放器。"
    },
    "Apache Axis2": {
        "type": ProductType.middleware,
        "producer": "Apache软件基金会",
        "desc": "Apache Axis2是WebService的一种框架，是在Apache Axis全功能Web服务框架基础上重构的版本，支持SOAP1.2/REST。"
    },
    "中国联通": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "PHPCMS": {
        "type": ProductType.cms,
        "producer": "酷溜网（北京）科技有限公司",
        "desc": "PHPCMS采用PHP5+MYSQL做为技术基础进行开发。9采用OOP（面向对象）方式进行基础运行框架搭建。模块化开发方式做为功能开发形式。框架易于功能扩展，代码维护，优秀的二次开发能力，可满足所有网站的应用需求。 5年开发经验的优秀团队，在掌握了丰富的WEB开发经验和CMS产品开发经验的同时，勇于创新追求完美的设计理念，为全球多达10万网站提供助力，并被更多的政府机构、教育机构、事业单位、商业企业、个人站长所认可。"
    },
    "卓繁CMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "WebLogic": {
        "type": ProductType.middleware,
        "producer": "Oracle",
        "desc": "WebLogic是美国Oracle公司出品的一个application server，确切的说是一个基于JAVAEE架构的中间件，WebLogic是用于开发、集成、部署和管理大型分布式Web应用、网络应用和数据库应用的Java应用服务器。将Java的动态功能和Java Enterprise标准的安全性引入大型网络应用的开发、集成、部署和管理之中。"
    },
    "科迈RAS系统": {
        "type": ProductType.cms,
        "producer": "深圳市科迈通讯技术有限公司",
        "desc": "科迈iRAS(Remote Application Solution)是中国首创远程快速应用接入方案，它结合TS终端技术，在提供网络互连架构的同时，可以集中发布各种应用程序，包括Web应用程序以及几乎所有部署在台式机上的应用程序。分析结果显示，维持iRAS正常使用所需要的带宽相当低，客户端提供最低28kbps的带宽即可实现快速的远程访问。"
    },
    "House5": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "House5房产信息网站系统是自主研发基于php+mysql的地方房产门户网站系统。"
    },
    "PHPOK": {
        "type": ProductType.cms,
        "producer": "深圳市锟铻科技有限公司",
        "desc": "这是一套允许用户高度自由配置的企业站程序，基于LGPL协议开源授权！"
    },
    "冠群金辰防病毒墙网关": {
        "type": ProductType.device,
        "producer": "北京冠群金辰软件公司",
        "desc": "冠群金辰防病毒墙网关。"
    },
    "上海鼎创通用型数字校园系统": {
        "type": ProductType.cms,
        "producer": "上海鼎创信息科技有限公司",
        "desc": "上海鼎创通用型数字校园系统。"
    },
    "淘客帝国CMS": {
        "type": ProductType.cms,
        "producer": "合肥九头鸟网络有限公司",
        "desc": None
    },
    "盛大游戏": {
        "type": ProductType.others,
        "producer": "上海数龙科技有限公司",
        "desc": "上海数龙科技有限公司盛大游戏站点。"
    },
    "DirPHP": {
        "type": ProductType.cms,
        "producer": "DirPHP",
        "desc": None
    },
    "Shopxp": {
        "type": ProductType.cms,
        "producer": "深圳市新普软件开发有限公司",
        "desc": "Shopxp网上购物系统是一个经过完善设计的经典商城购物管理系统，适用于各种服务器环境的高效网上购物网站建设解决方案。基于asp＋Access、Mssql为免费开源程序，在互联网上有广泛的应用。\n"
    },
    "SoftwareClassAd": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Vipshop": {
        "type": ProductType.cms,
        "producer": "唯品会",
        "desc": "唯品会官方站点。"
    },
    "Xiao5u(校无忧)": {
        "type": ProductType.others,
        "producer": "校无忧科技",
        "desc": "校无忧科技（简称：校无忧），位于中国安徽省六安市高新技术开发区，是专业从事教育软件教学应用研究与系统开发的高科技开发团队。"
    },
    "极限OA系统": {
        "type": ProductType.cms,
        "producer": "极限OA",
        "desc": "极限OA网络智能办公系统是一款办公软件，运行环境支持Win9x/Me/NT/2000/XP/2003。"
    },
    "Node.js": {
        "type": ProductType.middleware,
        "producer": "Node.js基金会",
        "desc": "Node.js是一个Javascript运行环境(runtime environment)，发布于2009年5月，由Ryan Dahl开发，实质是对Chrome V8引擎进行了封装。Node.js对一些特殊用例进行优化，提供替代的API，使得V8在非浏览器环境下运行得更好。"
    },
    "游戏风云": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "IIS": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": "iis是Internet Information Services的缩写，意为互联网信息服务，是由微软公司提供的基于运行Microsoft Windows的互联网基本服务。"
    },
    "皓峰防火墙": {
        "type": ProductType.device,
        "producer": "深圳市皓峰通讯技术有限公司",
        "desc": "皓峰防火墙系统。"
    },
    "OpenSSL": {
        "type": ProductType.middleware,
        "producer": "OpenSSL软件基金会",
        "desc": "OpenSSL 是一个安全套接字层密码库，囊括主要的密码算法、常用的密钥和证书封装管理功能及SSL协议，并提供丰富的应用程序供测试或其它目的使用。"
    },
    "WeMall": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "汇文软件": {
        "type": ProductType.others,
        "producer": "江苏汇文软件有限公司",
        "desc": "采用Client/Server、Browse/Server体系结构，运用中间件技术，创建开放的、创新的、可扩展的、 基于图书馆文献资源共享和文献服务共享的分布式应用软件系统。支持多种操作系统平台。如Windows 2003，各种Linux版本，Solaris， AIX， HP-UNIX，SCO UnixWare等 。采用大型关系型数据库Oracle作为数据库服务平台。支持TCP/IP、NetBEUI等多种通讯协议。"
    },
    "VPN": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": "虚拟专用网络的功能是：在公用网络上建立专用网络，进行加密通讯。在企业网络中有广泛应用。VPN网关通过对数据包的加密和数据包目标地址的转换实现远程访问。VPN有多种分类方式，主要是按协议进行分类。VPN可通过服务器、硬件、软件等多种方式实现。"
    },
    "7173游戏门户网": {
        "type": ProductType.others,
        "producer": "7173游戏门户网",
        "desc": "7173游戏门户网官方站点。"
    },
    "卓越课程中心": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "FastMeeting": {
        "type": ProductType.others,
        "producer": "深圳银澎云计算有限公司",
        "desc": "一款远程视频会议软件，效率工具。可以与其它用户进行面对面的多人语音、视频沟通，并可在会议中用文字聊天。广泛适用于企业开会、在线教育、在线培训、远程协助等场景。"
    },
    "海天OA": {
        "type": ProductType.cms,
        "producer": "北京联杰海天科技有限公司",
        "desc": "海天网络协同办公系统(海天OA)，是一套高质量、高效率、智能化的基于B/S结构的办公系统。产品特色：图形化流程设计、电子印章及手写签名痕迹保留等功能、灵活的工作流处理模式支持、完善的角色权限管理 、严密的安全性管理 、完备的二次开发特性。"
    },
    "美团": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "SimplyCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "联众世界": {
        "type": ProductType.others,
        "producer": "北京联众互动网络股份有限公司",
        "desc": "联众世界官方站点。"
    },
    "四创灾害预警系统": {
        "type": ProductType.device,
        "producer": "四创科技有限公司",
        "desc": "四创灾害预警系统。"
    },
    "大众点评": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "TinyRise": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "DTCMS": {
        "type": ProductType.cms,
        "producer": "深圳市动力启航软件有限公司",
        "desc": "启航内容管理系统(DTcms)是国内ASP.NET开源界少见的优秀开源网站管理系统，基于 ASP.NET(C#)+ MSSQL(ACCESS) 的技术开发，开放源代码。使用Webform普通三层架构开发模式，轻量级架构，后台使用原始的开发方式，无任何技术门槛，使得开发人员更容易上手。注重后台管理界面，采用Jquery和CSS3界面设计，兼容IE8及以上主流浏览器响应式后台管理界面，支持电脑、移动设备使用。"
    },
    "Gnat-TGP": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "鞍山银行": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "PICC中国人保": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "歪酷CMS": {
        "type": ProductType.cms,
        "producer": "歪酷CMS",
        "desc": "歪酷网站管理系统(歪酷CMS)是一款基于THINKPHP框架开发的PHP+MYSQL网站建站程序,本程序实现了文章和栏目的批量动态管理,支持栏目无限分类,实现多管理员管理,程序辅助功能也基本实现了常见的文章内关键字替换,文章内自动分页,手动分页,心情投票,留言和评论均采用了AJAX无刷新技术,数据库备份和还原,系统已经实现了伪静态,支持自定义伪静态后缀等等。"
    },
    "163(网易)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "PHPShop": {
        "type": ProductType.cms,
        "producer": "phpShop",
        "desc": "phpshop购物系统是完全按照web2.0标准构架的一套完整、专业的购物系统，完善的使用功能足以满足专业购物网站的需求，在用户体验方面使用了ajax技术，让网站耳目一新。程序基于PHP5.0和MYSQL5.0，运行更快，更安全。"
    },
    "91网": {
        "type": ProductType.others,
        "producer": "91网",
        "desc": None
    },
    "珍诚药店管理系统": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "Info_mdb": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "ShopNC": {
        "type": ProductType.cms,
        "producer": "天津市网城天创科技有限责任公司",
        "desc": "ShopNC商城系统，是天津市网城天创科技有限责任公司开发的一套多店模式的商城系统。"
    },
    "DigitalCampus": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "数字校园站点。"
    },
    "Egret(白鹭时代)": {
        "type": ProductType.cms,
        "producer": "北京白鹭",
        "desc": "Egret是一套完整的HTML5游戏开发解决方案。Egret中包含多个工具以及项目。Egret Engine是一个基于TypeScript语言开发的HTML5游戏引擎，该项目在BSD许可证下发布。"
    },
    "Euse TMS(益用在线培训系统)": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "完美世界": {
        "type": ProductType.others,
        "producer": "完美世界控股集团",
        "desc": "完美世界控股集团是全球领先的文化娱乐产业集团。长期以来，完美世界控股集团旗下产品遍布美、欧、亚等全球100多个国家和地区；在北京、香港、上海、重庆、成都、珠海，以及美国、荷兰、韩国、日本等地区设有20多个分支机构。目前，完美世界控股集团拥有影视、游戏、动画、漫画、文学、媒体、教育等业务板块。"
    },
    "贵州信息港": {
        "type": ProductType.others,
        "producer": "贵州信息港",
        "desc": "贵州信息港官方站点。"
    },
    "TP-Link": {
        "type": ProductType.device,
        "producer": None,
        "desc": None
    },
    "TCCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "TCCMS是一款具有良好的扩展性、安全、高效的内容管理系统。其核心框架TC，具备大数据量,高并发,易扩展等特点。"
    },
    "WordPress": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。"
    },
    "Apache Struts": {
        "type": ProductType.middleware,
        "producer": "Apache软件基金会",
        "desc": "Apache Struts框架是一个一个基于 Java Servlets,JavaBeans, 和 JavaServer Pages (JSP)的Web应用框架的开源项目，Struts基于Model-View-Controller (MVC)的设计模式，可以用来构件复杂的Web应用。它允许我们分解一个应用程序的商业逻辑、控制逻辑和表现逻辑的代码，使它的重用性和维护性更好。Struts框架是Jakarta工程的一部分，由Apache软件基金会管理，Struts框架提供以下服务： 作为MVC结构中的controller的servlet JSP里用于Bean管理、HTML和JavaScript生成、模板处理和流程控制的JSP标签库 用户国际化消息框架 一个JDBC的实现来定义数据员和数据库连接池 一个通用的错误和异常处理机制，包括从一个应用程序资源文件读取错误信息 XML语法分析 文件上载工具，注册机制。"
    },
    "Super8": {
        "type": ProductType.others,
        "producer": "速8酒店",
        "desc": "速8酒店官方站点"
    },
    "chanzhiEPS(蝉知门户系统)": {
        "type": ProductType.cms,
        "producer": "蝉知",
        "desc": "蝉知企业门户系统。"
    },
    "EcsCMS(易创思CMS)": {
        "type": ProductType.cms,
        "producer": "上海弘育信息技术有限公司",
        "desc": "易创思教育建站系统。"
    },
    "JeeCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "JEECMS是国内Java版开源网站内容管理系统（java cms、jsp cms）的简称。"
    },
    "万网": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "PageAdmin": {
        "type": ProductType.cms,
        "producer": "中山市南头镇华拓网络技术服务中心",
        "desc": "PageAdmins网站管理系统采用Div+Css标准化设计，符合W3C标准。兼容主流浏览器，网站系统可免费下载、免费使用、无使用时间与任何功能限制。主要用于公司企业网站、学校类和信息类网站搭建。"
    },
    "有道云": {
        "type": ProductType.others,
        "producer": "网易",
        "desc": "有道云笔记（原有道笔记）是2011年6月28日网易旗下的有道推出的个人与团队的线上资料库。"
    },
    "Baofeng": {
        "type": ProductType.others,
        "producer": "暴风影音",
        "desc": "暴风游戏是一款网页在线游戏。"
    },
    "sgc8000": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": "SGC8000 大型旋转机械在线状态监测及分析系统。"
    },
    "CTSProjects": {
        "type": ProductType.others,
        "producer": "CTSProjects",
        "desc": "CTS Projects & Software ClassAd是一个在线广告应用。"
    },
    "Wishnews(新华)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "GeniXCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "GeniXCMS是一个基于PHP的内容管理系统和框架（CMSF）。这是一个简单轻便的CMSF。非常适合中级PHP开发人员到Advanced Developer。需要一些手动配置才能使此应用程序正常工作。"
    },
    "QiboCMS(齐博CMS)": {
        "type": ProductType.cms,
        "producer": "广州齐博网络科技有限公司",
        "desc": "齐博CMS前身是“龙城”于大学期间也即2003年所创建的PHP168网站管理系统，它是国内主流CMS系统之一，曾多次被新浪网、腾讯网、凤凰网等多家大型IT媒体报道。齐博CMS目前已有数以万计的用户在使用，覆盖政府、 企业、科研教育和媒体等各个领域。"
    },
    "PHPB2B": {
        "type": ProductType.cms,
        "producer": "PHPB2B",
        "desc": "友邻B2B网站系统(PHPB2B)是一款基于PHP程序和Mysql数据库、以MVC架构为基础的开源B2B行业门户电子商务网站建站系统，系统代码完整、开源，功能全面，架构优秀，提供良好的用户体验、多国语言化及管理平台，是目前搭建B2B行业门户网站最好的程序。"
    },
    "Grayscale BandSite CMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "Xuezi(学子科技诊断测评系统)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "iWebshop": {
        "type": ProductType.cms,
        "producer": "济南爱程网络科技有限公司",
        "desc": "iWebShop是一款基于PHP语言及MYSQL数据库开发的B2B2C多用户开源免费的商城系统，系统支持平台自营和多商家入驻、集成微信商城、手机商城、移动端APP商城于一体，它可以承载大数据量且性能优良。"
    },
    "PHPDisk": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "是一套采用PHP和MySQL构建的网络硬盘(文件存储管理)系统，可替代传统的FTP文件管理。友好的界面，操作的便捷深受用户的欢迎。是一套可用于网络上文件办公、共享、传递、查看的多用户文件存储系统。广泛应用于互联网、公司、网吧、学校等地管理及使用文件，多方式的共享权限，全方位的后台管理，满足从个人到企业各方面应用的需求。"
    },
    "Nginx": {
        "type": ProductType.middleware,
        "producer": "Nginx",
        "desc": "Nginx (engine x) 是一个高性能的HTTP和反向代理服务器，也是一个IMAP/POP3/SMTP服务器。Nginx是由伊戈尔·赛索耶夫为俄罗斯访问量第二的Rambler.ru站点（俄文：Рамблер）开发的，第一个公开版本0.1.0发布于2004年10月4日。"
    },
    "企智通上网行为管理设备": {
        "type": ProductType.others,
        "producer": "北京宽广智通信息技术有限公司",
        "desc": "企智通上网行为管理设备。"
    },
    "大众网": {
        "type": ProductType.others,
        "producer": "山东大众传媒股份有限公司",
        "desc": "大众网网站配置文件读取分站配置文件读取。"
    },
    "易贷网": {
        "type": ProductType.others,
        "producer": "易贷网",
        "desc": "易贷网，中国专业的融资贷款网，正式开通于2009年1月。自正式开通以来，凭借强大的贷款行业背景支持、坚实的互联网技术研发及运营管理团队，迅速成为国内访问量最大的贷款网站。"
    },
    "新座标数字校园系统": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "PHPEMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "PHPEMS(PHP Exam Management System)在线模拟考试系统基于PHP+Mysql开发,支持多种题型和展现方式,是国内首款支持题冒题和手自动一体评分的PHP在线模拟考试系统。"
    },
    "杰诺瀚投稿系统": {
        "type": ProductType.cms,
        "producer": "南京杰诺瀚软件科技有限公司",
        "desc": None
    },
    "Mlairport": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Gzedu": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "中国平安": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Southidc": {
        "type": ProductType.cms,
        "producer": "南方数据",
        "desc": "南方数据企业CMS、企业网站SEO、网站优化、SEO搜索引擎优化机制、自助建站系统、前台全站采用静态html页面模板自动生成。"
    },
    "三唐实验室综合信息管理系统": {
        "type": ProductType.cms,
        "producer": "湖南三唐信息科技有限公司",
        "desc": "三唐实验室综合信息管理系统。"
    },
    "Bonfire": {
        "type": ProductType.others,
        "producer": None,
        "desc": "Ci-Bonefire is another Codeigniter based-on open source application."
    },
    "上网行为审计系统": {
        "type": ProductType.others,
        "producer": None,
        "desc": "13家厂商（17种设备）网上行为（审计）设备。"
    },
    "金蝶协同办公系统": {
        "type": ProductType.cms,
        "producer": "长沙鼎胜计算机科技有限公司",
        "desc": "金蝶办公自动化系统，是实现企业基础管理协作平台的知识办公系统，主要面向企事业单位部门、群组和个人，进行事务、流程和信息及时高效、有序可控地协同业务处理，创建企业电子化的工作环境，通过可视化的工作流系统和知识挖掘机制建立企业知识门户。"
    },
    "08CMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "08CMS是用PHP+MySQL开发的一套网站内容管理系统（即CMS系统），使用08CMS可以快速建立一个门户网站，比如：汽车门户网站、房产门户网站、产品库报价网站和家装门户网站等。"
    },
    "饿货帮": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Adobe": {
        "type": ProductType.others,
        "producer": "Adobe",
        "desc": "Adobe 创建于1983年，是世界领先数字媒体和在线营销方案的供应商。公司总部位于美国加利福尼亚州圣何塞，在世界各地员工人数约 7000名。Adobe 的客户包括世界各地的企业、知识工作者、创意人士和设计者、OEM合作伙伴，以及开发人员。"
    },
    "飞鱼星上网行为管理路由器": {
        "type": ProductType.device,
        "producer": "飞鱼星",
        "desc": "飞鱼星上网行为管理路由器。"
    },
    "DamiCMS(大米CMS)": {
        "type": ProductType.cms,
        "producer": "大米CMS",
        "desc": "大米CMS(又名3gcms)是一个免费开源、快速、简单的PC建站和手机建站集成一体化系统， 我们致力于为用户提供简单、快捷的PC建站和智能手机建站解决方案。"
    },
    "MangoBlog": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "StartBBS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "Startbbs - a simple & lightweight Forum. ... Hello, world! StartBBS 是一款优雅、开源、轻量社区系统，基于MVC架构。"
    },
    "Chamilo_LMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "FanWe(方维)": {
        "type": ProductType.others,
        "producer": "福建方维信息科技有限公司",
        "desc": "方维团购系统是基于groupon模式开发的团购系统。它可以让用户高效、快速、低成本的构建个性化、专业化、强大功能的团购网站。"
    },
    "北京精友": {
        "type": ProductType.others,
        "producer": "北京精友世纪软件技术有限公司",
        "desc": "北京精友世纪软件技术有限公司官方网站。"
    },
    "Horde": {
        "type": ProductType.others,
        "producer": "Horde",
        "desc": "Horde Framework是个以PHP为基础的架构，用来创建网络应用程式。"
    },
    "布丁移动": {
        "type": ProductType.others,
        "producer": "北京步鼎方舟科技有限公司",
        "desc": "布丁移动，专注于移动互联网O2O（Online to Offline）领域，移动互联网时代都市生活服务领军企业，。致力于推动国内移动电子凭证行业发展。休闲、娱乐、餐饮等都市生活服务为主要业务，推出布丁电影票、布丁优惠券、布丁外卖、布丁电影、布丁爱生活、布丁美食、微车等多款应用，支持iPhone和Android两个平台。"
    },
    "Bankrate": {
        "type": ProductType.others,
        "producer": "Bankrate",
        "desc": "银率网的url跳转。"
    },
    "AlstraSoft": {
        "type": ProductType.others,
        "producer": "Alstrasoft",
        "desc": "Alstrasoft provides web-based eBusiness solutions to companies intending to start their own online business. As a web development and software company, Alstrasoft specialize mainly in web design and software programming. AlstraSoft is built on many years of development experience and management talent."
    },
    "ibidian": {
        "type": ProductType.others,
        "producer": "风行",
        "desc": "风行旗下分站。"
    },
    "电子科技大学": {
        "type": ProductType.others,
        "producer": "电子科技大学",
        "desc": "电子科技大学分站任意文件包含漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。"
    },
    "德国使馆文化处": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "NITC": {
        "type": ProductType.cms,
        "producer": "宁波思迈尔网络科技有限公司",
        "desc": "NITC是由宁波思迈尔网络科技有限公司与宁波好的网络科技有限公司组织创办，联合国内较有实力的网络公司共同运营，为国内中小型企业与个人用户提供各类网络营销服务的平台。"
    },
    "ftp": {
        "type": ProductType.os,
        "producer": "FTP",
        "desc": "FTP 是File Transfer Protocol（文件传输协议）的英文简称，而中文简称为“文传协议”。用于Internet上的控制文件的双向传输。同时，它也是一个应用程序（Application）。基于不同的操作系统有不同的FTP应用程序，而所有这些应用程序都遵守同一种协议以传输文件。在FTP的使用当中，用户经常遇到两个概念：\"下载\"（Download）和\"上传\"（Upload）。\"下载\"文件就是从远程主机拷贝文件至自己的计算机上；\"上传\"文件就是将文件从自己的计算机中拷贝至远程主机上。用Internet语言来说，用户可通过客户机程序向（从）远程主机上传（下载）文件。"
    },
    "蓝凌EIS智慧协同平台": {
        "type": ProductType.cms,
        "producer": "深圳市蓝凌软件股份有限公司",
        "desc": "EIS4.0产品功能涵盖协同管理、知识管理、文化管理、个人工作及移动办公、项目管理、资源管理等多项扩展应用，充分满足成长型企业的各项需求。同时，智慧协同平台EIS也是蓝凌的渠道产品。"
    },
    "Mongodb": {
        "type": ProductType.middleware,
        "producer": "MongoDB",
        "desc": "MongoDB是一个基于分布式文件存储的数据库。由C++语言编写。旨在为WEB应用提供可扩展的高性能数据存储解决方案。"
    },
    "PHPWiki": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "PhpWiki是一个开源的wiki引擎程序，运行于PHP环境。"
    },
    "创维": {
        "type": ProductType.others,
        "producer": "创维",
        "desc": "创维分站系统文件非法读取。"
    },
    "vBulletin": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "Bulletin 是一个强大，灵活并可完全根据自己的需要定制的论坛程序套件。它使用目前发展速度最快的 Web 脚本语言编写： PHP，并且基于以高效和疾速著称的数据库引擎 MySQL。"
    },
    "Expansion": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "大连乾豪综合教务管理系统": {
        "type": ProductType.cms,
        "producer": "乾豪投资集团",
        "desc": "大连乾豪综合教务管理系统。"
    },
    "PSTAR": {
        "type": ProductType.others,
        "producer": None,
        "desc": "PSTAR-电子服务平台"
    },
    "Airpp": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "APPCMS": {
        "type": ProductType.cms,
        "producer": "贵州商擎科技有限公司",
        "desc": "AppCMS 是一套在国内知名的内容管理系统。"
    },
    "uWSGI": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": "uWSGI是一个Web服务器，它实现了WSGI协议、uwsgi、http等协议。Nginx中HttpUwsgiModule的作用是与uWSGI服务器进行交换。WSGI是一种Web服务器网关接口。它是一个Web服务器（如nginx，uWSGI等服务器）与web应用（如用Flask框架写的程序）通信的一种规范。"
    },
    "Suning": {
        "type": ProductType.others,
        "producer": "苏宁易购",
        "desc": "苏宁易购官方站点。"
    },
    "Zimbra": {
        "type": ProductType.cms,
        "producer": "Synacor",
        "desc": "Zimbra提供一套开源协同办公套件包括WebMail，日历，通信录，Web文档管理和创作。它最大的特色在于其采用Ajax技术模仿CS桌面应用软件的风格开发的客户端兼容Firefox,Safari和IE浏览器。"
    },
    "学位论文服务系统": {
        "type": ProductType.cms,
        "producer": "南宁旭东网络科技有限公司",
        "desc": None
    },
    "EasyTalk": {
        "type": ProductType.cms,
        "producer": "Easytalk",
        "desc": "EasyTalk是国内首款多用户PHP+Mysql开源微博客系统，支持网页、手机等多种方式发表和接收信息，EasyTalk微博客系统是由兰州乐游网络科技有限公司开发研制而成，全面符合国人的上网习惯，真正轻量级架构，使得使用者上手容易，管理者安装部署容易、管理便捷。EasyTalk功能强大，可二次开发性高，人性化的模板自定义功能大幅提高了用户的体验，因此EasyTalk相比国内其他微博客软件有绝对的优势！"
    },
    "Baicgov": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "链家": {
        "type": ProductType.others,
        "producer": "链家",
        "desc": "链家官方站点。"
    },
    "CuteCMS": {
        "type": ProductType.cms,
        "producer": "CuteCMS",
        "desc": "CuteCMS是基于PHP+MYSQL的网站内容管理系统，系统早期开始于2003年，作者一直套用这个系统开发了几百个网站系统，同时系统也不断在实践中完善。"
    },
    "中国电信": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "YunGouCMS(云购CMS)": {
        "type": ProductType.cms,
        "producer": "重庆韬龙网络科技有限公司",
        "desc": "YunGouCMS(云购CMS)"
    },
    "eYou": {
        "type": ProductType.others,
        "producer": "北京亿中邮信息技术有限公司",
        "desc": "亿邮邮件系统是一款强大的邮件系统，广泛应用于学校、政府机构。"
    },
    "Daiant(贷蚂蚁)": {
        "type": ProductType.others,
        "producer": "蚂蚁科技金融",
        "desc": "蚂蚁科技金融官方站点。"
    },
    "Vanke": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "EeagdEDU": {
        "type": ProductType.cms,
        "producer": "广东省教育考试院",
        "desc": "广东省教育考试院本地文件包含。"
    },
    "PHP": {
        "type": ProductType.middleware,
        "producer": "PHP",
        "desc": "PHP（外文名:PHP: Hypertext Preprocessor，中文名：“超文本预处理器”）是一种通用开源脚本语言。"
    },
    "LiteCart": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "启博科技淘店系统": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "PHPShe": {
        "type": ProductType.cms,
        "producer": "灵宝简好网络科技有限公司",
        "desc": "PHPSHE网上商城系统具备电商零售业务所需的所有基本功能,以其安全稳定、简单易用、高效专业等优势赢得了用户的广泛好评,为用户提供了一个低成本、高效率的网上商城服务。"
    },
    "PiaoYou(票友软件)": {
        "type": ProductType.cms,
        "producer": "上海盛代信息科技有限公司",
        "desc": "票友软件是一款用于航空票务代理专用机票管理系统，集成网上订票管理、电话录音弹屏、企业差旅管理、同业订单管理、会员管理、积分管理、短信发送、员工管理、报表生成、财务管理等强大功能，广泛应用于有各航空票务代理人及航空售票点，帮助您提高工作效率，迅速了解客户的需求，极大提高业务成交量，提升客户满意度，协助您在激烈的市场竞争中脱颖而出。"
    },
    "Bocweb": {
        "type": ProductType.cms,
        "producer": "杭州博采网络科技股份有限公司",
        "desc": "博采网络商城系统 - 打造专业的B2C、B2B2C网上商城系统,面向零售商及品牌商,可帮助商家快速搭建专属的商城、网上商城、零售商城、品牌官网。"
    },
    "GrayCMS": {
        "type": ProductType.cms,
        "producer": "GrayCMS",
        "desc": "GrayCMS是一种开源的基于PHP的Web内容管理系统。"
    },
    "OpenSNS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "一起飞": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "迅雷": {
        "type": ProductType.others,
        "producer": "迅雷公司",
        "desc": "迅雷是迅雷公司开发的互联网下载软件。本身不支持上传资源，只提供下载和自主上传。迅雷下载过相关资源，都能有所记录。迅雷是一款基于多资源超线程技术的下载软件，作为“宽带时期的下载工具”，迅雷针对宽带用户做了优化，并同时推出了“智能下载”的服务。"
    },
    "U17(有妖气)": {
        "type": ProductType.others,
        "producer": "有妖气原创漫画梦工厂",
        "desc": "有妖气原创漫画梦工厂官方站点。"
    },
    "39健康网": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "机锋网": {
        "type": ProductType.others,
        "producer": "机锋网",
        "desc": "机锋网官方站点。"
    },
    "Coolpad": {
        "type": ProductType.others,
        "producer": "宇龙计算机通信科技（深圳）有限公司",
        "desc": "酷派旗下分站SQL注入。"
    },
    "TodayMail": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "WebSphere": {
        "type": ProductType.middleware,
        "producer": "IBM",
        "desc": "WebSphere 是 IBM 的软件平台。它包含了编写、运行和监视全天候的工业强度的随需应变 Web 应用程序和跨平台、跨产品解决方案所需要的整个中间件基础设施，如服务器、服务和工具。WebSphere 提供了可靠、灵活和健壮的软件。"
    },
    "PHPWeb": {
        "type": ProductType.cms,
        "producer": "嘉兴市网聚网络技术有限公司",
        "desc": "通过对各种行业网站的细分研究和精心设计，制作好各种现成网站打包出售。"
    },
    "SEMCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "华视校园电视网": {
        "type": ProductType.others,
        "producer": "江苏华视文化传媒有限公司",
        "desc": "华视校园电视网是在校园的公共场所安装电视机，并通过网页播控的多媒体广播系统。播出内容由高校的宣传部门主管，并服务于高校思政建设、校园文化建设、学术分享和快速发布通知、通告的校园新媒体。"
    },
    "EduSohoCMS": {
        "type": ProductType.cms,
        "producer": "杭州阔知网络科技有限公司",
        "desc": "EduSoho在线教育平台，提供了多样化的教学功能，包括传统的课件展示、在线测验、作业、资料下载、在线交流等，更有兼具MOOC平台的功能，如在线教学直播和在线教学视频，这样一整套完善、简洁、流畅的教学体验使得在线教育更加人性化。"
    },
    "Info_PHPmyadmin": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "天柏在线培训系统": {
        "type": ProductType.others,
        "producer": "上海天柏科技公司",
        "desc": "天柏在线培训系统(Timber Training System)是上海天柏科技公司开发的新一代网络学习平台,它在承接传统教育的基础之上,充分体现了E-learning的设计理念,为现代学习型组织提供了卓有成效的学习与培训方案,通过本系统提供的在线学习、在线考试和在线评估等方式,轻松完成针对员工制订的培训计划。"
    },
    "MetInfo": {
        "type": ProductType.cms,
        "producer": "长沙米拓信息技术有限公司",
        "desc": "MetInfo企业网站管理系统是一个功能完善的营销型企业网站管理平台，PHP+MYSQL架构，全站内置SEO优化机制，界面简洁，操作方便，个人网站永久免费。"
    },
    "Autohome(汽车之家)": {
        "type": ProductType.others,
        "producer": " 汽车之家",
        "desc": None
    },
    "UjnEDU(济南大学)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "正方协同办公系统": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "协同办公系统的设计目标是帮助各部门快速构建起一个安全、可靠、易用的文档一体化办公环境，实现公文处理的自动化，同时作为内部通讯和信息共享的平台。 "
    },
    "Elastix": {
        "type": ProductType.others,
        "producer": None,
        "desc": "Elastix is an open source unified communications server software that brings together IP PBX, email, IM, faxing and collaboration functionality. It has a Web interface and includes capabilities such as a call center software with predictive dialing."
    },
    "硅谷动力": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Minerva": {
        "type": ProductType.others,
        "producer": None,
        "desc": "Chris Smith Minerva Build 238"
    },
    "无限城市": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "interact": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "JumboECMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "JumboECMS是针对企业用户专门改写的基于JumboTCMS的一个版本。 模块有：单页、新闻、下载、产品、在线订购、留言等等，支持中英文。"
    },
    "ShopBuilder": {
        "type": ProductType.cms,
        "producer": "上海远丰信息科技（集团）有限公司",
        "desc": "ShopBuilder是专为大中型企业开发的专业级电子商务商城系统，功能强大，安全便捷，可承载千万级访问量，让企业低成本快速构建在线商城，开启电子商务业务，系统开源发售，可以根据公司业务需要，制定专门的业务流程和各种功能模块，已成为众多大中型企业做电商会选的产品。"
    },
    "RuvarHRM": {
        "type": ProductType.cms,
        "producer": "广州市璐华计算机科技有限公司",
        "desc": "广州市璐华计算机科技有限公司是一家eHR系统,人力资源管理软件,eHR系统,人事管理软件,eHR软件,人力资源管理系统,广州OA,政府OA软件开发商。"
    },
    "SiteServer": {
        "type": ProductType.cms,
        "producer": "北京百容千域软件技术开发有限公司",
        "desc": "SiteServer CMS是定位于中高端市场的CMS内容管理系统，能够以最低的成本、最少的人力投入在最短的时间内架设一个功能齐全、性能优异、规模庞大并易于维护的网站平台。"
    },
    "totalsoft": {
        "type": ProductType.cms,
        "producer": "重庆图腾软件发展有限公司",
        "desc": " 整个系统采用国际流行的Browser / WebServer / DBServer 三层或 Client / Server 双层体系结构， 后台选用大型关系数据库Sql Server 2000 作为系统平台（并全面支持Sybase和Oracle数据库）。"
    },
    "迈普": {
        "type": ProductType.others,
        "producer": "迈普通信技术股份有限公司",
        "desc": "迈普，是中国主流的网络及行业应用解决方案供应商，产品和解决方案大量应用于银行、保险、政府、运营商、军队、电力等行业，致力于以技术和服务改变人们的工作和生活方式。"
    },
    "TOM.COM": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "iGENUS(爱琴思邮件系统)": {
        "type": ProductType.cms,
        "producer": "爱琴思科技(成都)有限公司",
        "desc": "爱琴思邮件系统。"
    },
    "金山": {
        "type": ProductType.others,
        "producer": "金山软件",
        "desc": None
    },
    "Info_DS_Store(.DS_Store文件泄露)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Happigo": {
        "type": ProductType.cms,
        "producer": "快乐购物股份有限公司",
        "desc": "快乐购物2005年底由湖南广播影视集团与湖南卫视联合注资亿元成立，2006年3月由合资公司湖南快乐购物股份有限公司开业运营。快乐购从“电视百货、连锁经营”起步，定位“媒体零售、电子商务”，致力跨行业、跨媒体、跨地区发展，十二年来成长为国内新一代家庭购物行业领军者。"
    },
    "EMC Cloud Tiering Appliance": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "微擎": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "台州市极速网络CMS": {
        "type": ProductType.cms,
        "producer": "台州市极速网络有限公司",
        "desc": "极速CMS政务站群内容管理系统按照政府门户网站考核标准为基础，集成信息公开、网上办事、互动交流、网络问政、在线服专题专栏等政务网站核心模块内容而开发的内容管理系统；系统同时支持信息报送、绩效考核等子系统的数据对接；站群B/S架构，支持主站跟子站独立部署，又支持数据相互互通"
    },
    "Hebfda": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Info_shell": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Dreamershop(梦想家网店系统)": {
        "type": ProductType.cms,
        "producer": "北京智鹏鼎创科技有限公司",
        "desc": " DreamerShop网店提供了关于零售和批发行业在互联网上进行销售的综合解决方案，通过这个系统，网商们可以迅速、安全的搭建起自己的网上销售商店，开始商务之路。"
    },
    "Comtrend Router": {
        "type": ProductType.device,
        "producer": "康全电讯",
        "desc": "康全电讯路由器"
    },
    "RISING": {
        "type": ProductType.others,
        "producer": "北京瑞星网安技术股份有限公司",
        "desc": "瑞星官方站点。"
    },
    "腾讯": {
        "type": ProductType.others,
        "producer": "Tencent",
        "desc": None
    },
    "电力监控系统": {
        "type": ProductType.device,
        "producer": None,
        "desc": "电力监控系统站点。"
    },
    "远古流媒体系统": {
        "type": ProductType.others,
        "producer": "江苏远古信息技术有限公司",
        "desc": "远古是VIEWGOOD的俗称(以下用VIEWGOOD介绍),VIEWGOOD视频点播系统模块是流媒体服务平台解决方案的重要模块之一，可以独立运营。"
    },
    "真旅网": {
        "type": ProductType.others,
        "producer": "真旅网",
        "desc": "真旅网 （Travelzen）是中国最先进的“网上旅行社”，成立于2007年，由中国最大航空票务代理商之一的上海不夜城国际旅行社与国际私募基金共同打造，2011年 1月真旅网与上海不夜城国际旅行社正式合并，全面的资源融合，极大的推动在线旅游业务快速增长。"
    },
    "YinDaiTong(银贷通)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Sphider": {
        "type": ProductType.others,
        "producer": None,
        "desc": "sphider是一个基于php的轻量级站内搜索。"
    },
    "Alipay": {
        "type": ProductType.others,
        "producer": "Alipay",
        "desc": "alipay是指阿里巴巴旗下的支付工具支付宝，是国内领先的第三方支付平台。支付宝，是以每个人为中心，以实名和信任为基础的一站式场景平台。支付宝不仅支持线上消费支付，也通过扫码支付的形式拓展了线下支付服务，包括餐饮、超市、便利店、出租车、公共交通等。"
    },
    "华创路由器": {
        "type": ProductType.device,
        "producer": "北京华夏创新科技有限公司",
        "desc": "华创路由器。"
    },
    "Loveit": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "XDCMS(旭东企业网站管理系统)": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "XDcms是南宁旭东网络科技有限公司推出的一套开源的通用的内容管理系统。主要使用php+mysql+smarty技术基础进行开发，XDcms采用OOP（面向对象）方式进行基础运行框架搭建。模块化开发方式做为功能开发形式。框架易于功能扩展，代码维护，二次开发能力优秀。"
    },
    "WeaTherMap": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": None
    },
    "CMS通用插件swf": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": "相信很多站长对swfupload.swf、uploadify.swf这样的文件不陌生，做站的时候常常看到。实际上这是一个著名的利用swf异步上传的一个插件。\n        它可以很好解决异步上传、多文件异步上传的问题，很快这个插件就红遍了cms界，各大cms都使用这个swf来处理上传问题。"
    },
    "泛微OA": {
        "type": ProductType.cms,
        "producer": "上海泛微网络科技股份有限公司",
        "desc": "作为协同管理软件行业的领军企业，泛微有业界优秀的协同管理软件产品。在企业级移动互联大潮下，泛微发布了全新的以“移动化 社交化 平台化 云端化”四化为核心的全一代产品系列，包括面向大中型企业的平台型产品e-cology、面向中小型企业的应用型产品e-office、面向小微型企业的云办公产品eteams，以及帮助企业对接移动互联的移动办公平台e-mobile和帮助快速对接微信、钉钉等平台的移动集成平台等等。"
    },
    "企慧通培训系统": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Info_Backup(网站备份文件泄露)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "OSClass": {
        "type": ProductType.cms,
        "producer": "Osclass",
        "desc": "osclass是一个开源项目，允许您在没有任何技术知识的情况下轻松创建分类网站。"
    },
    "Clicksor": {
        "type": ProductType.others,
        "producer": "Clicksor",
        "desc": "Clicksor是国外一家以浮动广告、弹窗广告为主的广告联盟。"
    },
    "Newedos(菲斯特诺期刊系统)": {
        "type": ProductType.cms,
        "producer": "北京菲斯特诺科技有限公司",
        "desc": "菲斯特诺期刊网络编辑平台，系统运行环境：windows NT或以上操作系统，IIS6.0，SQL数据库，ASP.NET2.0。主要功能是图书馆建设。"
    },
    "Mallbuilder商城系统": {
        "type": ProductType.cms,
        "producer": "远丰集团",
        "desc": "MallBuilder是一款基于PHP+MYSQL的多用户网上商城解决方案，利用MallBuilder可以快速建立一个功能强大的类似京东商城、天猫商城、1号店商城的网上商城，或企业化、行业化、本地化和垂直化的多用户商城，MallBuilder是B2Bbuilder的姊妹篇，她除了延续B2Bbuilder的众多优点之外，还增加了许多新功能，使操作更加简单，功能更加完善，性能更加稳定的多用户商城建设系统。"
    },
    "OTCMS": {
        "type": ProductType.cms,
        "producer": "网钛科技",
        "desc": " 网钛CMS(OTCMS) PHP版 基于PHP+sqlite/mysql的技术架构，UTF-8编码，以简单、实用、傻瓜式操作而闻名，无论在功能，人性化，还是易用性方面，都有了长足的发展，网钛CMS的主要目标用户锁定在中小型网站站长，让那些对网络不是很熟悉，对网站建设不是很懂又想做网站的人可以很快搭建起一个功能实用又强大，操作人性又易用。"
    },
    "搜狐": {
        "type": ProductType.others,
        "producer": None,
        "desc": "搜狐是一家互联网中文门户网站。1995年，搜狐创始人张朝阳从美国麻省理工学院毕业回到中国，利用风险投资创建了爱特信信息技术有限公司，1998年正式推出搜狐网。2000年，搜狐在美国纳斯达克证券市场上市。\n搜狐开发的产品有搜狗拼音输入法、搜狗五笔输入法、搜狗音乐盒、搜狗浏览器、搜狐彩电、独立的搜索引擎搜狗和网游门户畅游。"
    },
    "KesionCMS": {
        "type": ProductType.cms,
        "producer": "厦门科汛软件有限公司",
        "desc": "KesionCMS是ASP管理系统。KesionCMS系统功能完善，覆盖面广、扩展性强、负载能力好、模板调用非常灵活、管理方便，因此不仅适合于建设一般企业、政府、学校、个人等小型网站，同时也适合于建设地方门户、行业门户、收费网站等大中型网站。"
    },
    "SePortal": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "SePortal - The Weblog System."
    },
    "DigiEye 3G": {
        "type": ProductType.device,
        "producer": "迈瑞",
        "desc": "DigiEye 3G(software version 3.19.30004) Backdoor."
    },
    "电子政务网": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "Pirelli": {
        "type": ProductType.others,
        "producer": None,
        "desc": "Pirelli路由器。"
    },
    "TOUR旅游网站管理系统": {
        "type": ProductType.cms,
        "producer": "四川思途智旅软件有限公司",
        "desc": "tour旅游网站管理系统,快速上手,操作简单,轻松管理旅游网站!tour旅游网站管理系统,用户体验超棒的一款旅游网站系统!"
    },
    "Caohua(草花游戏)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Ndstar": {
        "type": ProductType.cms,
        "producer": "南大之星",
        "desc": "南大之星档案管理软件，本系统采用浏览器/服务器（B/S）结构，具有维护方便，不需要另外安装客户端软件，客户端只需要一台联网（局域网、校园网、互联网）的计算机就可以了，具有操作简单、维护方便、安全可靠、功能齐全等特点。"
    },
    "115网盘": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "TRS IDS(拓尔思身份服务器系统)": {
        "type": ProductType.cms,
        "producer": "北京拓尔思信息技术股份有限公司",
        "desc": "拓尔思身份服务器系统。"
    },
    "PHPMyWind": {
        "type": ProductType.cms,
        "producer": "PHPMyWind",
        "desc": "PHPMyWind 是一款基于PHP+MySQL开发，符合W3C标准的建站引擎。"
    },
    "JieqiCMS(杰奇CMS)": {
        "type": ProductType.cms,
        "producer": "杭州杰奇网络科技有限公司",
        "desc": "杰奇网站管理系统（简称杰奇CMS）是从深受好评的杰奇小说连载系统基础上发展而来的全功能、高性能、高可靠性CMS系统。 是企业和个人建设各类门户网站、信息发布网站的理想平台。"
    },
    "中企动力门户CMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "PhpMyRecipes": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "phpMyRecipes is a simple application for storing and retrieving recipes. It uses a web-based interface, for ease of use across any system, and a MySQL database backend for storing the recipes."
    },
    "京瓷打印机": {
        "type": ProductType.device,
        "producer": "\t\n京瓷集团",
        "desc": "京瓷打印机。"
    },
    "惠尔顿上网行为管理系统": {
        "type": ProductType.cms,
        "producer": "惠尔顿",
        "desc": "惠尔顿上网行为管理系统"
    },
    "金盘软件": {
        "type": ProductType.others,
        "producer": "北京金盘鹏图软件技术有限公司",
        "desc": None
    },
    "Piwigo": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "Piwigo是一个基于MySQL5与PHP5开发的相册系统.提供基本的发布和管理照片功能,按多种方式浏览如类别,标签,时间等。"
    },
    "百为流控路由": {
        "type": ProductType.device,
        "producer": "深圳市百为通达科技有限公司",
        "desc": "百为流控是一款追求完美上网体验、追求最大带宽利用率的多功能路由器，因其颠覆性的核心功能智能流控而名为百为流控路由器。"
    },
    "金山逍遥": {
        "type": ProductType.others,
        "producer": "成都西山居世游科技有限公司",
        "desc": "91Xoyo游戏中心是集Flash小游戏等在线游戏形式于一体的游戏玩家互动、交流平台，其中91Xoyo小游戏门户是国内最有影响力的Flash小游戏网站之一。"
    },
    "Snaplb": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "YidaCMS(易达CMS)": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "YidaCMS免费开源网站管理系统，是一款简单、实用、高效的网站建站软件。YidaCMS免费开源网站管理系统是基于微软的WINDOWS IIS平台，采用ASP语言ACCESS和MSSQL双数据库开发完成。\n整体系统采用强大的HTML引擎，模板设计和程序语言完全分开，这会让您在设计模板时更加快捷和方便。全站静态化及标准的URL路径，更加让百度等搜索引擎青睐。"
    },
    "Easethink(易想团购管理系统)": {
        "type": ProductType.cms,
        "producer": "易想团购",
        "desc": "易想团购管理系统是一套定位中高端市场的团购内容管理系统,能够以最低的成本,最少的人力投入在最短的时间架设一个功能齐全、性能优异、规模庞大并易于维护的网站平台。"
    },
    "Info_waf": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "360Shop(启博微分销)": {
        "type": ProductType.cms,
        "producer": "杭州启博科技有限公司",
        "desc": "360SHOP自主研发的360SHOP商城网店系统，目前已服务于4万5000家用户，是企业及网商进行网络销售、在线营销、分销批发的有力工具与销售渠道，其中\"淘店通\"系统开辟了互联网新的行业格局，将互联网的应用书写了新的篇章。"
    },
    "5Clib(五车图书管理系统)": {
        "type": ProductType.cms,
        "producer": "五车信息技术（北京）有限公司",
        "desc": "51Clib是一个专业的电子图书管理系统，秉承专业资源服务于专业人群的理念，向社会提供高标准、高价值的电子图书和人性化、个性化的服务，是教学、科研、工作、生活必不可少的知识资源中心！"
    },
    "People(人民)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "YaBB.pl": {
        "type": ProductType.others,
        "producer": None,
        "desc": "YaBB.pl是一个基于Web的公告牌脚本程序。"
    },
    "GNUboard": {
        "type": ProductType.cms,
        "producer": "韩国Sir公司",
        "desc": "Gnuboard是韩国Sir公司开发一套PHP+Mysql可扩展论坛程序。将主程序与Skin（风格文件）完全剥离，通过skin的编辑可以制作人才就业网站、房产信息平台、供求信息发布、甚至可以作为企业产品展示。"
    },
    "Joomla!": {
        "type": ProductType.cms,
        "producer": "Joomla!",
        "desc": "Joomla!是一套自由、开放源代码的内容管理系统，以PHP撰写，用于发布内容在万维网与内部网，通常被用来搭建商业网站、个人部落格、资讯管理系统、Web 服务等，还可以进行二次开发以扩充使用范围。其功能包含可提高效能的页面快取、RSS馈送、页面的可打印版本、新闻摘要、部落格、投票、网站搜寻、与语言国际化。Joomla!是一套自由的开源软件，使用GPL授权，任何人随时都能下载 Joomla! 并立即使用它。"
    },
    "Mailgard": {
        "type": ProductType.cms,
        "producer": "深圳市河辰通讯技术有限公司",
        "desc": "佑友是深圳市河辰通讯技术有限公司的注册商标，公司成立于1998年，是技术型公司，市场和技术人员的比例是1:1。公司是信息化建设方案的提供商，也是深圳市政府协议采购供应品牌。主力产品是Mailgard佑友系列邮件服务器，垃圾邮件过滤网关，邮件网关，防火墙，VPN，上网行为管理等等。"
    },
    "任我行CRM": {
        "type": ProductType.cms,
        "producer": "成都任我行信息技术有限公司",
        "desc": "任我行CRM软件，是构架在互联网上，以客户为中心，以销售团队或营销系统管理为核心，以规范企业系统性和流程性、提升执行力为诉求的，涉及企业全方位资源管理的“企业运营管理平台”(Enterprise Operation Management Platform)。"
    },
    "MacCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "PHP开源CMS，完全开源、强劲功能、卓越性能、安全健壮。超级易用、模板众多、插件齐全、资源丰富。构架稳健，实现平滑升级。"
    },
    "PJBlog": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "PJBlog是由舜子（陈子舜，英文名字PuterJam，PJblog就是以他英文名字缩写命名的，他本人就职于腾讯公司QZONE开发组）所开发的一套开源免费的中文个人博客系统程序，采用asp+Access的技术，PJBlog同时支持简繁中文，UTF-8编码，相对于其他系统，PJBlog具有相当高的运作效能以及更新率，也支持目前Blog所使用的新技术。"
    },
    "Zblog": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "Z-Blog是由RainbowSoft Studio开发的一款小巧而强大的基于Asp和PHP平台的开源程序，其创始人为朱煊(网名：zx.asd)。"
    },
    "Ztgame": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "宝驾": {
        "type": ProductType.others,
        "producer": "宝驾（北京）信息技术有限公司",
        "desc": "宝驾官方网站。"
    },
    "莱克斯上网行为管理系统": {
        "type": ProductType.cms,
        "producer": "莱克斯",
        "desc": "莱克斯上网行为管理系统。"
    },
    "Ecshop": {
        "type": ProductType.cms,
        "producer": "上海商派网络科技有限公司",
        "desc": "ECSHOP是一款开源免费的网上商店系统。"
    },
    "网神": {
        "type": ProductType.others,
        "producer": "网神信息技术（北京）股份有限公司",
        "desc": "网神信息技术（北京）股份有限公司是集技术研发、生产制造、综合服务于一体的高科技信息安全方案、产品及服务提供商。"
    },
    "美图秀秀": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Dreamgallery": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "UC网站": {
        "type": ProductType.others,
        "producer": "UC网站",
        "desc": "UC官方站点。"
    },
    "URP教务系统": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "FSMCMS": {
        "type": ProductType.cms,
        "producer": "北京东方文辉信息技术有限公司",
        "desc": "FSMCMS是北京东方文辉信息技术有限公司开发的一套内容管理系统。"
    },
    "任子行网络审计系统": {
        "type": ProductType.others,
        "producer": "任子行网络技术股份有限公司",
        "desc": "任子行网络审计系统。"
    },
    "ExponentCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "TRS InfoRadar(拓尔思网络信息雷达系统)": {
        "type": ProductType.cms,
        "producer": "北京拓尔思信息技术股份有限公司",
        "desc": "TRS网络信息雷达系统的主要功能是实时监控和采集目标网站的内容，对采集到的信息进行过滤阴门动分类处理，最终将最新内容及时发布出来，实现统一的信息导航功能，同时提供包括全文检索。彐期(范围)检索·标题检索、URL检索等在内的全方位信息查询手段。"
    },
    "Moxa": {
        "type": ProductType.device,
        "producer": "台湾moxa科技股份有限公司",
        "desc": "Moxa致力于发展及制造信息联网产品，提供客户具成本效益且稳定性高的串口通信解决方案、串口设备联网解决方案、及工业以太网解决方案。事实，Moxa将大部分的研发力量均集中在串口设备联网及以太网交换的技术上，因为使用以太网作为传输主干已成为趋势。除此之外，Ethernet LAN已在全球普及，即使是非网络专业人员也能轻松地设置以太网通讯应用。"
    },
    "诚信档案": {
        "type": ProductType.others,
        "producer": "广东上下五千年资信网络科技有限公司",
        "desc": "诚信档案是在全国范围内的各个领域建立的各种诚信体系，旨在促进社会发展、打造诚信、构建和谐社会。"
    },
    "PHPMoAdmin": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "phpMoAdmin是一款便捷的在线MongoDB管理工具，可用于创建、删除和修改数据库和索引，提供视图和数据搜索工具，提供数据库启动时间和内存的统计，支持JSON格式数据的导入导出的php应用。"
    },
    "中华网": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "浙大升腾软件数字房产系统": {
        "type": ProductType.others,
        "producer": None,
        "desc": " "
    },
    "LNMP": {
        "type": ProductType.others,
        "producer": None,
        "desc": "LNMP指的是一个基于CentOS/Debian编写的Nginx、PHP、MySQL、phpMyAdmin、eAccelerator一键安装包。可以在VPS、独立主机上轻松的安装LNMP生产环境。"
    },
    "泛华保险": {
        "type": ProductType.others,
        "producer": "泛华保险服务集团",
        "desc": "泛华保险官方站点。"
    },
    "STCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": " STCMS音乐系统是一个优秀的音乐内容管理系统，本系统基于PHP+Mysql，采用MVC模式开发，支持模板标签，调用灵活。"
    },
    "MySQL": {
        "type": ProductType.middleware,
        "producer": "MySQL",
        "desc": "MySQL是一个关系型数据库管理系统，由瑞典MySQL AB 公司开发，目前属于 Oracle 旗下产品。MySQL 是最流行的关系型数据库管理系统之一，在 WEB 应用方面，MySQL是最好的 RDBMS (Relational Database Management System，关系数据库管理系统) 应用软件"
    },
    "ThinkPHP": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": "ThinkPHP是为了简化企业级应用开发和敏捷WEB应用开发而诞生的。最早诞生于2006年初，2007年元旦正式更名为ThinkPHP，并且遵循Apache2开源协议发布。ThinkPHP从诞生以来一直秉承简洁实用的设计原则，在保持出色的性能和至简的代码的同时，也注重易用性。并且拥有众多原创功能和特性，在社区团队的积极参与下，在易用性、扩展性和性能方面不断优化和改进。"
    },
    "PHPYun": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "PHP云人才管理系统，专业的人才招聘网站系统开源程序，采用PHP 和MySQL 数据库构建的高效的人才与企业求职招招聘系统源码。"
    },
    "Collabnet": {
        "type": ProductType.others,
        "producer": "CollabNet",
        "desc": "CollabNet致力于提供专为分布式团队设计的集成、开放开发应用平台。通过集成具有协作、项目管理和应用程序生命周期管理功能的软件配置管理、变更管理和问题跟踪工具，CollabNet 简化了任何规模组织的开发。CollabNet 平台集成了广泛的软件开发工具，为分布式应用程序生命周期管理提供了完整的解决方案。"
    },
    "华泰人寿": {
        "type": ProductType.others,
        "producer": "华泰人寿",
        "desc": "华泰人寿官方站点。"
    },
    "HeeritOA(希尔OA)": {
        "type": ProductType.cms,
        "producer": "北京希尔",
        "desc": "希尔办公自动化系统旨在为高校内部各级单位之间建立起一种开放的、网络化的、高效的办公新环境，以一套完善的支持群体协作、流程控制、信息发布及控制功能的应用软件。"
    },
    "KenticoCMS": {
        "type": ProductType.cms,
        "producer": "ASP.NET开发商",
        "desc": " Kentico CMS是一个企业级Web内容管理系统和客户体验管理系统，它提供了一整套的功能，内置多国语言支持，用于在内部或云中基于Microsoft ASP.NET平台构建网站、Intranet、社区站点和电子商务解决方案。"
    },
    "PHPStat": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "PHPStat 网站流量统计,是通过统计网站访问者的访问来源、访问时间、访问内容等访问信息,加以系统分析,进而总结出访问者访问来源、爱好趋向、访问习惯等一些共性数据，为网站进一步调整做出指引的一门新型用户行为分析技术。"
    },
    "ElasticSearch": {
        "type": ProductType.others,
        "producer": "Elasticsearch ",
        "desc": "ElasticSearch是一个基于Lucene的搜索服务器。它提供了一个分布式多用户能力的全文搜索引擎，基于RESTful web接口。Elasticsearch是用Java开发的，并作为Apache许可条款下的开放源码发布，是当前流行的企业级搜索引擎。设计用于云计算中，能够达到实时搜索，稳定，可靠，快速，安装使用方便。"
    },
    "百度": {
        "type": ProductType.others,
        "producer": "百度",
        "desc": None
    },
    "SEACMS(海洋CMS)": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "SeaCMS是一套使用PHP编写的免费、开源的网站内容管理系统。该系统主要被设计用来管理视频点播资源。"
    },
    "Bash": {
        "type": ProductType.os,
        "producer": "Linux",
        "desc": "bash 是一个为GNU计划编写的Unix shell。它的名字是一系列缩写：Bourne-Again SHell — 这是关于Bourne shell（sh）的一个双关语（Bourne again / born again）。Bourne shell是一个早期的重要shell，由史蒂夫·伯恩在1978年前后编写，并同Version 7 Unix一起发布。bash则在1987年由布莱恩·福克斯创造。在1990年，Chet Ramey成为了主要的维护者。"
    },
    "724CMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "PloneCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "深澜认证平台": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "微信管理系统": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "蓝太平洋": {
        "type": ProductType.others,
        "producer": "北京蓝太平洋科技股份有限公司",
        "desc": "蓝太平洋网站决策支持系统：对各类大小型网站进行网站分析、流量统计。"
    },
    "74CMS(骑士CMS)": {
        "type": ProductType.cms,
        "producer": "太原迅易科技有限公司",
        "desc": "骑士cms人才系统，是一项基于PHP+MYSQL为核心开发的一套免费 + 开源专业人才网站系统。软件具执行效率高、模板自由切换、后台管理功能方便等诸多优秀特点。"
    },
    "FeiFeiCMS": {
        "type": ProductType.cms,
        "producer": " 飞飞影视系统团队工作室",
        "desc": "飞飞CMS又名飞飞PHP影视系统,包括有PHP版(ppvod)与ASP版(adncms),飞飞CMS由飞飞老谭独立开发,免费提供给站长使用,最大亮点是一键采集海量影视资源!"
    },
    "凤凰网": {
        "type": ProductType.others,
        "producer": "凤凰网",
        "desc": "凤凰网官方站点。"
    },
    "TomPDA": {
        "type": ProductType.others,
        "producer": None,
        "desc": "中国最大的二手手机交易平台,提供全国各地二手手机,二手笔记本,二手数码产品交易信息。"
    },
    "Supesite": {
        "type": ProductType.cms,
        "producer": "北京康盛新创科技有限责任公司",
        "desc": "SupeSite是一套拥有独立的内容管理(CMS)功能，并集成了Web2.0社区个人门户系统X-Space，拥有强大的聚合功能的社区门户系统。 SupeSite可以实现对站内的论坛(Discuz!)、个人空间(X-Space)信息进行内容聚合。任何站长，都可以通过SupeSite，轻松构建一个面向Web2.0的社区门户。"
    },
    "NatShell": {
        "type": ProductType.device,
        "producer": "成都蓝海卓越科技有限公司",
        "desc": "NatShell宽带认证计费系统"
    },
    "Hitweb": {
        "type": ProductType.others,
        "producer": "HITWEB",
        "desc": "HITWEB是一个基于PHP、PHPLib和MySQL的站点程序，可提供各种分类的Internet站点集合。 "
    },
    "华为": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "征途": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Oppo": {
        "type": ProductType.others,
        "producer": "OPPO",
        "desc": "OPPO官方站点。"
    },
    "多玩": {
        "type": ProductType.others,
        "producer": "广州华多网络科技有限公司",
        "desc": "多玩分站存在SQL注入漏洞。"
    },
    "Nongyou": {
        "type": ProductType.cms,
        "producer": "山东农友软件有限公司",
        "desc": "农友软件多年来致力于农村、农业、农民的“三农”信息化建设，是国内领先的“三农”信息化建设全面解决方案提供商，同时也是国内最大的“三农”信息化服务提供商。"
    },
    "EspCMS(易思CMS)": {
        "type": ProductType.cms,
        "producer": "洪湖尔创网联信息技术有限公司",
        "desc": "PHP免费企业建站CMS、企业CMS平台、自助建站企业网站,可用于企业网站建设、外贸网站建设、营销网站建设、集团网站建设等。"
    },
    "Hnkpxx(科普信息)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "风讯CMS": {
        "type": ProductType.cms,
        "producer": "风讯",
        "desc": "风讯网站管理系统包括了信息采集、整理、分类、审核、发布和管理的全过程，具备完善的信息管理和发布管理功能，是企事业单位网站、内部网站和各类ICP网站内容管理和维护的理想工具。"
    },
    "深澜深澜计费引擎": {
        "type": ProductType.device,
        "producer": None,
        "desc": None
    },
    "Soffice": {
        "type": ProductType.cms,
        "producer": "深圳赛飞软件有限公司",
        "desc": "Soffice，赛飞软件Soffice小组主要作品，国内重量级全方位协同办公平台和中小企业云优质基础产品，覆盖30人-3000人的企业级用户，提供数字办公全面解决方案，是目前功能最完整技术最先进的协同办公平台之一。"
    },
    "方正证券": {
        "type": ProductType.others,
        "producer": "方正证券",
        "desc": "方正证券官方站点。"
    },
    "双汇网": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "强智教务系统": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "DuomiCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "Shopv8商城系统": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "《Shopv8商城系统》是一款Asp商城系统，运行环境支持ASP。"
    },
    "宝创科技MSA": {
        "type": ProductType.others,
        "producer": "宝创科技",
        "desc": "金盾MSA互联网管理网关，采用1U-4U机架式千兆结构，全面满足新一代网关对管理、安全、速度的要求。多路监控管理。支持多种接入方式,包括旁路，网桥、网关以及混合路由方式。使用基于SSL的B/S管理架构，十分友好的界面操作，通过网络可以方便管理；支持SSH加密远端管理和本地终端管理。"
    },
    "WanCMS": {
        "type": ProductType.cms,
        "producer": "嘉兴市米洛网络科技有限公司",
        "desc": "wancms 程序,全开源不加密,php+mysql,提供手册,便于二次开发.后台操作简单,功能强大。"
    },
    "完美时空": {
        "type": ProductType.others,
        "producer": "完美世界（北京）网络技术有限公司",
        "desc": "完美时空客服自助平台。"
    },
    "亿赛通": {
        "type": ProductType.others,
        "producer": "北京亿赛通科技发展有限责任公司",
        "desc": "亿赛通是中国文档安全管理系统的生产者，最大的数据泄露防护产品解决方案提供商，以推动信息安全技术发展、加强信息安全管理、保护核心知识资产和机密信息安全为已任，为政府、部队、企业组织提供信息安全管理咨询服务和数据泄露防护（DLP）软件产品和基于行业用户需求的数据泄露防护（DLP）解决方案。"
    },
    "Jtsh": {
        "type": ProductType.others,
        "producer": None,
        "desc": "上海交通网。"
    },
    "Zoomla": {
        "type": ProductType.cms,
        "producer": "Zoomla!逐浪CMS官网",
        "desc": "Zoomla!逐浪®CMS是运行在微软大数据平台上的一款卓越网站内容管理系统，基于.NET4.5框架，SQL Server数据库平台（扩展支持Oracle甲骨文、MYSQL诸多数据库）、纯净的MVC架构，系统在优秀的内容管理之上，提供OA办公、移动应用、微站、微信、微博等能力，完善的商城、网店等管理功能，并包括教育模块、智能组卷、在线试戴、在线考试及诸多应用。Zoomla!逐浪®CMS不仅是一款网站内容管理系统，更是企业信息化的起点，也是强大的WEB开发平台，完全免费开放，丰富的学习资源和快速上手教程，并结合自主的字库、Webfont解决方案、逐浪云，为中国政府、军工、世界五百强企业以及诸多站长、开发者提供卓越的软件支持。"
    },
    "HiShop易分销系统": {
        "type": ProductType.cms,
        "producer": "长沙海商网络技术有限公司",
        "desc": "HiShop是国内领先的商城系统及微分销系统与新零售系统提供商.为企业提供新零售系统,微分销系统,网上商城系统,B2B2C商城系统,多用户商城系统,分销小程序商城系统。"
    },
    "UniPortal": {
        "type": ProductType.others,
        "producer": "华苓科技股份有限公司 ",
        "desc": "UniPortal是一套先进的企业资讯入口网站(EIP,Enterprise Information Portal)。能帮助企业能有效工作，简单、好用又能快速使用的云端协同作业的产品，内含各项工作任务、团队沟通、讯息公告、经营维运等办公所需功能模组，更把各种工作资讯、系统集中于单一平台，满足每日办公需求。"
    },
    "Info_hg": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "189(电信)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "JiandanCMS(简单CMS)": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "iDVR": {
        "type": ProductType.others,
        "producer": None,
        "desc": "iDVR移动视频管理软件。"
    },
    "Jenkins": {
        "type": ProductType.middleware,
        "producer": "Jenkins",
        "desc": "Jenkins是一个开源软件项目，是基于Java开发的一种持续集成工具，用于监控持续重复的工作，旨在提供一个开放易用的软件平台，使软件的持续集成变成可能。"
    },
    "3gmeeting": {
        "type": ProductType.others,
        "producer": "熔点网讯（北京）科技有限公司",
        "desc": "3gmeeting高清视讯系统是熔点网讯（北京）科技有限公司针对3G时代移动网络与固网融合，用户随时随地接入互联网进行交流沟通的发展趋势，面向企业用户推出的通过现有高清终端、标清终端、PC、3G手机和电话等多种终端，在任何时间、地点均可提供实时多点视频通讯服务。"
    },
    "Mafia Moblog": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "网易": {
        "type": ProductType.others,
        "producer": "网易",
        "desc": "网易官方站点"
    },
    "DswjCMS": {
        "type": ProductType.cms,
        "producer": "DswjCMS",
        "desc": "DSWJCMS是一家专注打造开源P2P网贷系统的企业，提供P2P，P2C等多个版本产品。"
    },
    "MvMmall": {
        "type": ProductType.cms,
        "producer": "迈维软件有限公司",
        "desc": "MvMmall提供了国内最好最漂亮的免费php多用户商城系统,网络分销系统,开源网店系统,网店联盟营销平台,专业的网络商店系统及商城系统。"
    },
    "DreamAccount": {
        "type": ProductType.others,
        "producer": "DreamAccount",
        "desc": "DreamAccount是一款基于PHP的成员管理程序。"
    },
    "政府采购系统": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "天空下载站": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "10010(联通)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Hanweb(大汉)": {
        "type": ProductType.cms,
        "producer": "南京大汉网络有限公司",
        "desc": "大汉版通JCMS内容管理系统是基于J2EE构架设计的内容管理系统，多用于政府门户网站。"
    },
    "7k7kbox": {
        "type": ProductType.others,
        "producer": None,
        "desc": "  7k7k游戏盒是一款非常易用的互联网综合游戏工具， 用过同类盒子产品的玩家们应该都有印象，类似7K7K游戏盒的软件通常只有单一的单机游戏供玩家下载游玩，而忽略了同样是游戏组成部分的网络游戏。"
    },
    "QYKCMS(青云客博客CMS)": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "万户OA": {
        "type": ProductType.cms,
        "producer": "万户网络",
        "desc": "万户软件是一个坚持网络风格是最大限度提升软件健壮性的一种有效手段，因为这样一来，决定应用并发数的并不是软件平台本身，而是硬件和网络速度；也就是说，从理论上讲，类似万户协同ezOFFICE这样的软件平台没有严格的并发数限制。"
    },
    "爱问": {
        "type": ProductType.others,
        "producer": "新浪",
        "desc": "“爱问iAsk”是新浪完全自主研发的搜索产品，充分体现人性化应用的产品理念，为广大网民提供全新搜索服务。"
    },
    "Insight(英赛特仓储管理系统)": {
        "type": ProductType.cms,
        "producer": "宁波市江东英赛特软件有限公司",
        "desc": "英赛特仓储管理系统。"
    },
    "LTPower(广东力拓软件)": {
        "type": ProductType.others,
        "producer": "广东力拓软件",
        "desc": "LTPower(广东力拓软件)高校在用系统。"
    },
    "惠普": {
        "type": ProductType.others,
        "producer": "惠普",
        "desc": "惠普打印机。"
    },
    "AVCON6": {
        "type": ProductType.others,
        "producer": "上海华平信息技术股份有限公司",
        "desc": "“AVCON6 (AVCON UCC统一协同通讯系统）”是一套集视音频编码技术、网络传输技术、数据会议技术、网络存储技术于一体的运营级的监控指挥方案，它将视频会议技术和传统监控技术整合于一身，并赋予监控新的概念，是对传统监控的设计思想一种创新和发展。使监控行业的向“范围广、图像清、时延低、使用易”方面发展，利用它无论区域的大小、身处何处，主管领导都能第一时间掌握突发事情的实时情况，组织相关力量开展应急处理，实现远程监控指挥，使监控将不仅仅为了看到问题，而是为了解决问题，具备主控、指挥的能力，实现监控概念的一大创。"
    },
    "UCenter": {
        "type": ProductType.cms,
        "producer": "北京康盛新创科技有限责任公司",
        "desc": "UCenter 的中文意思就是“用户中心”，其中的 U 代表 User 也代表 You ，取其中的含义就是“用户中心”，或者说“你（最终用户）的中心”。 UCenter 是 Comsenz 旗下各个产品之间信息直接传递的一个桥梁，通过 UCenter 站长可以无缝整合 Comsenz 系列产品，实现用户的一站式注册、登录、退出以及社区其他数据的交互。"
    },
    "电信路由器": {
        "type": ProductType.device,
        "producer": "电信",
        "desc": "电信路由器。"
    },
    "Budejie": {
        "type": ProductType.others,
        "producer": "精灵在线网络技术（北京）有限公司",
        "desc": "百思不得姐——最大的娱乐创意社区。致力于提供各种搞笑、萌、动漫、幽默图片，汇聚大量的超火爆、超级冷、高笑点的段子。"
    },
    "Cicro": {
        "type": ProductType.device,
        "producer": "Cicro",
        "desc": "Cicro网络设备。"
    },
    "EnableQ": {
        "type": ProductType.cms,
        "producer": "北京科维能动信息技术有限公司",
        "desc": "EnableQ在线问卷调查引擎是一款通用的在线调查问卷管理平台。"
    },
    "西华大学": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Vicworl": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "Vicworl，视频播客系统、网络直播(视频/音频)系统、智能录制系统、网络电视台系统。功能强大而完善。"
    },
    "智旅天下景区分销系统": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Weiphone": {
        "type": ProductType.others,
        "producer": "威锋网",
        "desc": "威锋网自建立之日起一直是最具人气的中文iPhone社区，给广大iPhone爱好者提供了一个自由交流，探讨，学习的平台，为iPhone在中国的应用及普及发挥了领军作用！"
    },
    "RuvarOA(璐华OA)": {
        "type": ProductType.cms,
        "producer": "广州市璐华计算机科技有限公司",
        "desc": "璐华OA办公自动化系统（政府版）是广州市璐华计算机科技有限公司专门针对我国党政机关、事业单位开发，采用组件技术和Web技术相结合，基于Windows平台，构建在大型关系数据库管理系统基础上的，以行政办公为核心，以集成融通业务办公为目标，将网络与无线通讯等信息技术完美结合在一起设计而成的新型办公自动化应用系统。"
    },
    "易想团购": {
        "type": ProductType.others,
        "producer": None,
        "desc": "易想团购系统,国内最优秀的PHP开源团购系统"
    },
    "Info_Manage": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "PHPMPS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "php分类信息发布系统是一款免费开源的分类信息程序,适用于建立本地信息站点。"
    },
    "苏亚星校园管理系统": {
        "type": ProductType.cms,
        "producer": "南京苏亚星资讯科技开发有限公司",
        "desc": "苏亚星校园网软件系统是苏亚星公司将校园网中的校务管理系统、资源库管理系统、VOD点播系统、校园网站和虚拟社区进行整合而形成的校园网综合应用平台，结合了全国几万所学校的使用需求、教育部教育管理信息化标准和公司的技术成就，它覆赢了学校信息化教育中的管理、教学、资源、娱乐、窗口等各个应用环仃，各子系统的资源都可以充分的实现共享，是校园网建设中最理想的应用软件系统。"
    },
    "长安信托": {
        "type": ProductType.others,
        "producer": "长安信托",
        "desc": "长安信托官方网站。"
    },
    "YXCMS(新云CMS)": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "YXcms是一款基于PHP+MySql开发的网站管理系统，采用轻量级MVC设计模式。"
    },
    "中科网威防火墙": {
        "type": ProductType.device,
        "producer": "北京中科网威信息技术有限公司",
        "desc": "中科网威防火墙产品，基于L2-7层访问应用控制,集成了防火墙、IPS入侵检测、DDoS/DOS防护、AV病毒防护；实现对内网全面安全防护，如应用扫描、病毒检测防护、Web应用防护、木马黑客防护、流控带宽管理、多线路负载均衡等。可为企业、运营商、高端行业用户提供卓越性能的安全防火墙方案。"
    },
    "CTSCMS": {
        "type": ProductType.cms,
        "producer": "CTSCMS",
        "desc": "CTSCMS旅游网站管理系统（以下简称CTSCMS）是专注于旅游电子商务的旅游行业旅行社旅游网站系统程序源码，含多套旅游网站模板，是最专业的旅游网站建设服务提供商。"
    },
    "东风汽车网": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "iPowerCMS": {
        "type": ProductType.cms,
        "producer": "重庆鼎维网络科技有限公司",
        "desc": "iPowerCMS是鼎维网络自主开发并定型网站内容管理系统。"
    },
    "grafana": {
        "type": ProductType.middleware,
        "producer": "Grafana",
        "desc": "Grafana是一个可视化面板（Dashboard），有着非常漂亮的图表和布局展示，功能齐全的度量仪表盘和图形编辑器，支持Graphite、zabbix、InfluxDB、Prometheus和OpenTSDB作为数据源。Grafana主要特性：灵活丰富的图形化选项；可以混合多种风格；支持白天和夜间模式；多个数据源。"
    },
    "Gw(大智慧)": {
        "type": ProductType.others,
        "producer": "上海大智慧股份有限公司",
        "desc": "上海大智慧股份有限公司官方站点。"
    },
    "PLCRouter": {
        "type": ProductType.cms,
        "producer": None,
        "desc": ""
    },
    "JISUCMS(台州市极速网络CMS)": {
        "type": ProductType.cms,
        "producer": "台州市极速网络有限公司",
        "desc": None
    },
    "搜狗": {
        "type": ProductType.others,
        "producer": "搜狗",
        "desc": "搜狗官方站点。"
    },
    "Airkunming(昆明航空)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Info_PHPinfo": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Zuitu(最土团购)": {
        "type": ProductType.others,
        "producer": "最土团购",
        "desc": "最土团购系统是国内最专业、功能最强大的GroupOn模式的免费开源团购系统平台，专业技术团队、完美用户体验与极佳的性能，立足为用户提供最值得信赖的免费开源网上团购系统。"
    },
    "WebServer": {
        "type": ProductType.os,
        "producer": None,
        "desc": "Web Server中文名称叫网页服务器或web服务器。WEB服务器也称为WWW(WORLD WIDE WEB)服务器，主要功能是提供网上信息浏览服务。"
    },
    "IP.Board": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "易维论坛。"
    },
    "上海冰峰VPN路由设备": {
        "type": ProductType.device,
        "producer": "上海冰峰计算机网络技术有限公司",
        "desc": "上海冰峰VPN路由设备。"
    },
    "Yonyou(用友)": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "安脉学校综合管理平台": {
        "type": ProductType.cms,
        "producer": "上海安脉计算机科技有限公司",
        "desc": "采用B/S结构.NET技术，支持IE/Google/火狐/360等主流浏览器，支持云平台，有多元化的用户群，进行统一身份论证，符合《教育管理信息化标准》的要求。"
    },
    "chanzhiCMS(蝉知CMS)": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "连邦软件": {
        "type": ProductType.others,
        "producer": "邯郸市连邦软件",
        "desc": "邯郸市连邦软件政府网上审批系统。"
    },
    "Maidanla(周边云)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Jiemian": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "eWebEditor": {
        "type": ProductType.others,
        "producer": "福州极限软件开发有限公司",
        "desc": "eWebEditor是一个所见即所得的在线编辑器。顾名思义，就是能在网络上使用所见即所得的编辑方式进行编辑图文并茂的文章、新闻、讨论贴、通告、记事等多种文字处理应用。"
    },
    "airlines": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "皓翰数字化校园平台": {
        "type": ProductType.cms,
        "producer": "浙江皓翰教育科技有限公司",
        "desc": "浙江皓翰教育科技有限公司数字化校园平台系统。"
    },
    "中华电信": {
        "type": ProductType.others,
        "producer": "中华电信股份有限公司",
        "desc": "中华电信股份有限公司是台湾省最大的固网电信、数据通信及移动通讯公司。由台湾当局交通部电信总局发展而来，原为国有企业，1997年之后逐渐民营化。\n中华电信提供通讯、互联网、电视等多种业务，从营收来看，中华电信是台湾省最大的电信公司。"
    },
    "Dahuatech": {
        "type": ProductType.cms,
        "producer": "浙江大华技术股份有限公司",
        "desc": "大华城市安防监控系统平台。"
    },
    "北京电视台": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "PHPVibe": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "PHPVibe是国外一款视频CMS系统。"
    },
    "Ksbao(考试宝)": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "太极行政服务中心": {
        "type": ProductType.cms,
        "producer": "太极计算机股份有限公司",
        "desc": None
    },
    "Ruankao": {
        "type": ProductType.others,
        "producer": None,
        "desc": "“软考”报名网官方站点。"
    },
    "ThinkSNS": {
        "type": ProductType.cms,
        "producer": "智士软件（北京）有限公司",
        "desc": "ThinkSNS开源社交网站APP系统,含微博,论坛,问答,即时聊天,资讯CMS,投票,礼物商城,商城等功能应用。"
    },
    "ZTE": {
        "type": ProductType.others,
        "producer": "中兴通讯股份有限公司",
        "desc": "中兴通讯股份有限公司，全球领先的综合通信解决方案提供商，中国最大的通信设备上市公司。主要产品包括：2G/3G/4G/5G无线基站与核心网、IMS、固网接入与承载、光网络、芯片、高端路由器、智能交换机、政企网、大数据、云计算、数据中心、手机及家庭终端、智慧城市、ICT业务，以及航空、铁路与城市轨道交通信号传输设备。"
    },
    "科威网址盒子导航": {
        "type": ProductType.device,
        "producer": "科威软件工作室",
        "desc": "科威盒子导航系统是基于科威网址导航系统开发的全新的网址导航系统，它采用PHP语言，使用MySQL数据库。它打破了传统网址导航站的风格，拥有全新的界面设计，给用户全新的体验。它拥有功能完整的后台管理系统，可以不限分类级数，无限添加站点。可以自定义模板，多种模板随意切换，一键生成全站HTML,便于搜索引擎收录。可自定义广告，使网站可以获得收益。科威网址导航系统还有用户收藏和浏览记录功能，使网站功能更加强大。"
    },
    "浪潮通用型电商系统": {
        "type": ProductType.cms,
        "producer": "浪潮",
        "desc": "浪潮通用型电商系统。"
    },
    "Resin": {
        "type": ProductType.middleware,
        "producer": "CAUCHO",
        "desc": "Resin是CAUCHO公司的产品，是一个非常流行的application server，对servlet和JSP提供了良好的支持，性能也比较优良，resin自身采用JAVA语言开发。"
    },
    "派网软件": {
        "type": ProductType.others,
        "producer": "北京派网软件有限公司",
        "desc": "派网网络设备。"
    },
    "电信": {
        "type": ProductType.others,
        "producer": "电信路由器",
        "desc": None
    },
    "Cttis": {
        "type": ProductType.others,
        "producer": "中国铁通",
        "desc": "中国铁通江苏分公司WebDAV的远程执行代码。"
    },
    "SeawindSolution": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "CMSimple": {
        "type": ProductType.cms,
        "producer": "CMSimple",
        "desc": "CMSimple是个最小，最灵巧，最简单的内容管理系统。可为短小精干！它是一个个人用户维护一个站点的理想工具。"
    },
    "途牛": {
        "type": ProductType.others,
        "producer": "途牛",
        "desc": "途牛官方站点。"
    },
    "ChinaUnix": {
        "type": ProductType.cms,
        "producer": "ChinaUnix",
        "desc": "ChinaUnix.net（以下简称CU）是一个以讨论Linux/Unix类操作系统技术、软件开发技术、数据库技术和网络应用技术等为主的开源技术社区网站。"
    },
    "社区矫正管理系统": {
        "type": ProductType.cms,
        "producer": "成都翰东科技有限公司",
        "desc": "翰东社区矫正定位管控系统，是应用于司法社区矫正管理的信息化系统，通过实时人员定位、实时信息交互实现对社区矫正人员的管理，实现针对社区矫正人员的实时位置监控、历史轨迹回放、越界报警、通知公告、考核管理等功能，实现社区矫正智能化管理，提高社区矫正工作的管理人性化和管理工作效率。"
    },
    "ProFTPD": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": "ProFTPD:一个Unix平台上或是类Unix平台上（如Linux, FreeBSD等）的FTP服务器程序。"
    },
    "SouthSoft": {
        "type": ProductType.cms,
        "producer": "南京南软科技有限公司",
        "desc": "南软公司分别在教育、政府机关、烟草、企业等多个领域展开了软件研发，电子商务应用及系统集成工作。"
    },
    "多多淘宝客": {
        "type": ProductType.others,
        "producer": "广州凌科普华网络科技有限公司",
        "desc": "多多淘宝客返利建站系统。"
    },
    "酷狗": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "TaoCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "taoCMS是一个完善支持多数据库(Sqlite/Mysql)的CMS网站内容管理系统，是国内最小巧的功能完善的基于 php+SQLite/php+Mysql的CMS。体积小速度快，所有的css、JavaScript均为手写代码，无任何垃圾代码，采用严格的数据过滤，保证服务器的安全稳定！"
    },
    "Clipbucket": {
        "type": ProductType.cms,
        "producer": "Clipbucket",
        "desc": "Clipbucket是一个免费提供给社区的开源多媒体管理脚本。"
    },
    "艺龙": {
        "type": ProductType.others,
        "producer": "艺龙旅行网",
        "desc": "艺龙旅行网 (NASDAQ: LONG)是中国领先的在线旅行服务提供商之一，通过网站、24小时预订热线以及手机艺龙网三大平台，为消费者提供酒店、机票和度假等全方位的旅行产品预订服务。艺龙旅行网通过提供强大的地图搜索、酒店360度全景、国内外热点目的地指南和用户真实点评等在线服务，使用户可以在获取广泛信息的基础上做出旅行决定。"
    },
    "Changhong": {
        "type": ProductType.others,
        "producer": "长虹",
        "desc": "长虹SSLvpn远程执行后门。"
    },
    "南京师友软件": {
        "type": ProductType.cms,
        "producer": "南京师友软件有限公司",
        "desc": "南京师友软件网站集群管理系统。"
    },
    "国富安应用安全网关": {
        "type": ProductType.device,
        "producer": "北京国富安电子商务安全认证有限公司",
        "desc": "国富安应用安全网关产品。"
    },
    "IDevSpot PHPLinkExchange": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "育友通用数字化校园平台": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "弘智房产管理系统": {
        "type": ProductType.cms,
        "producer": "武汉弘智科技",
        "desc": "武汉弘智科技房产管理系统"
    },
    "广州大学": {
        "type": ProductType.others,
        "producer": "广州大学",
        "desc": "广州大学站点。"
    },
    "Redis": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": "Redis is an open source, BSD licensed, advanced key-value cache and store. It is often referred to as a data structure server since keys can contain strings, hashes, lists, sets, sorted sets, bitmaps and hyperloglogs."
    },
    "Koolearn(新东方)": {
        "type": ProductType.others,
        "producer": "新东方",
        "desc": "新东方官方站点。"
    },
    "中国移动": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "上海寰创运营商WLAN": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "金龙一卡通系统": {
        "type": ProductType.device,
        "producer": "哈尔滨新中新华科电子设备有限公司",
        "desc": "金龙卡金融化一卡通校园卡查询系统。"
    },
    "Lecture": {
        "type": ProductType.others,
        "producer": None,
        "desc": "北大讲座网。"
    },
    "悟空CRM": {
        "type": ProductType.cms,
        "producer": "郑州卡卡罗特软件科技有限公司",
        "desc": "悟空CRM系统是一款开源免费的通用企业客户关系管理平台软件,采用先进的LAMP架构,具有良好的开放性、可扩展性、安全性和透明性。"
    },
    "Hikvision": {
        "type": ProductType.others,
        "producer": "海康威视",
        "desc": "海康威视多媒体设备。"
    },
    "KingCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "哈尔滨工程大学": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "爱爱医": {
        "type": ProductType.others,
        "producer": "珠海健康云科技有限公司",
        "desc": "爱爱医是由珠海健康云科技有限公司研发的，为医学从业人员提供医学专业技术和经验交流，提供执业医师考试辅导，提供全科社区卫生医学的专业论坛，是中国最具人气的专门服务于医务人员的医学网站，它致力于开展人性化、科学化、信息化的互联网医疗知识技术的交流，推动数字化医学事业发展，始建2002年7月，前身为中国医学生论坛。发展七年以来已颇具规模和影响力，注册医生会员数已达到百万以上。其旗下主要特色栏目有 爱爱医医学论坛，医生博客，医学资讯，爱爱医人网等频道。"
    },
    "Cnsun(太阳网)": {
        "type": ProductType.others,
        "producer": "深圳市中阳通讯有限公司",
        "desc": "专注于人脸识别产品、智能家居产品及云对讲产品的软硬件产品及云开台开发。"
    },
    "Qyer": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "第一财经": {
        "type": ProductType.others,
        "producer": "第一财经",
        "desc": "第一财经分站存在文件包含漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。"
    },
    "有图互联": {
        "type": ProductType.others,
        "producer": "北京有图互联科技股份有限公司",
        "desc": "有图互联是中国领先的数字媒体技术及服务提供商，有图互联以自身创新发展和产业整合并举，坚持技术 服务的双轮驱动战略，自主研发跨媒体设计工具及云平台，为专业人士和媒体、出版、教育、大企业等领域提供有竞争力的s'h媒体应用解决方案。"
    },
    "双杨OA系统": {
        "type": ProductType.cms,
        "producer": "上海双杨电脑高科技开发公司",
        "desc": None
    },
    "GreenOrange(上海青橙)": {
        "type": ProductType.others,
        "producer": "上海青橙",
        "desc": "青橙Green Orange，是一家专注于移动智能终端研发、生产、销售和移动互联网应用的创新型的高科技公司，以手机产业和移动互联的经验和智慧，推出以“我”为核心青橙定制手机，将C2B模式的全球化为目标。"
    },
    "中软华泰防火墙": {
        "type": ProductType.device,
        "producer": None,
        "desc": None
    },
    "去哪儿": {
        "type": ProductType.others,
        "producer": "去哪儿",
        "desc": "去哪儿网官方站点。"
    },
    "天睿电子图书管理系统": {
        "type": ProductType.cms,
        "producer": "成都天睿信息技术有限公司",
        "desc": "图书CMS是一套阅读书籍系统，基于PHPCMF框架架构，拥有相当强大的内容管理模式和灵活的扩展性能。"
    },
    "PPS": {
        "type": ProductType.others,
        "producer": "PPS",
        "desc": "PPS官方站点。"
    },
    "天融信审计系统": {
        "type": ProductType.device,
        "producer": "天融信",
        "desc": "天融信运维安全审计系统集账号管理、授权管理、认证管理和综合审计于一体，为企业提供统一框架，整合企业服务器、网络设备、主机系统，确保合法用户安全、方便使用特定资源。既能有效地保障合法用户的权益，又能有效地保障支撑系统安全可靠地运行。"
    },
    "BSPlayer": {
        "type": ProductType.device,
        "producer": None,
        "desc": "BS.Player - 最棒的多媒体播放器 (DivX, HD 和 AVC视频, 电影, 音频, DVD, YouTube) 全球通用。"
    },
    "Fluxbb": {
        "type": ProductType.cms,
        "producer": "FluxBB",
        "desc": "FluxBB是个快速、轻巧的PHP架构的网络论坛系统，以GPL协议发行。 FluxBB的宗旨是变得与别的论坛系统相比更快、更小、少图形，也具有较少的功能与更精简的程式码。"
    },
    "国联证劵": {
        "type": ProductType.others,
        "producer": "国联证劵",
        "desc": "国联证劵官方站点。"
    },
    "方正Apabi数字资源平台": {
        "type": ProductType.cms,
        "producer": "北京方正阿帕比技术有限公司",
        "desc": "北京方正阿帕比技术有限公司是北大方正信息产业集团有限公司旗下专业的数字出版技术及产品提供商。方正阿帕比公司自2001年起进入数字出版领域，在继承并发展方正传统出版印刷技术优势的基础上，自主研发了数字出版技术及整体解决方案，已发展成为全球领先的数字出版技术提供商。"
    },
    "山东大学": {
        "type": ProductType.others,
        "producer": "山东大学",
        "desc": "山东大学站点。"
    },
    "天生创想OA": {
        "type": ProductType.cms,
        "producer": "北京天生创想信息技术有限公司",
        "desc": None
    },
    "中海达VNet6专业型参考站接收机": {
        "type": ProductType.device,
        "producer": None,
        "desc": None
    },
    "SpeedCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": " 标准化企业内容管理系统(SpeedCMS) php框架采用SpeedPHP js框架采用jquery开发的一款软件。"
    },
    "ShopNum1": {
        "type": ProductType.cms,
        "producer": "武汉群翔软件有限公司",
        "desc": "ShopNum1网店系统是武汉群翔软件有限公司自主研发的基于 WEB 应用的 B/S 架构的B2C网上商店系统，主要面向中高端客户， 为企业和大中型网商打造优秀的电子商务平台，ShopNum1运行于微软公司的 .NET 平台，采用最新的 ASP.NET 3.5技术进行分层开发。拥有更强的安全性、稳定性、易用性。"
    },
    "ZZCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "CsCMS": {
        "type": ProductType.cms,
        "producer": "CsCMS",
        "desc": "程氏CMS专门为中小站长解决建站难的问题、一键采集、一键生成静态、一键安装,傻瓜式的建站程序。"
    },
    "ShadowsIT": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "NiubiCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "牛逼CMS 地方门户网站源码系统 PHP免费版。功能包含：新闻、房产、人才、汽车、二手、分类信息、交友、商城、团购、知道、论坛、DM读报、优惠券、本地商家、商家名片等功能。"
    },
    "PKPMBS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "PKPMBS工程质量监督站信息管理系统。"
    },
    "ROCBOSS微社区": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "HDwiki": {
        "type": ProductType.others,
        "producer": "互动在线（北京）科技有限公司",
        "desc": "互动维客开源系统（HDwiki）作为中国第一家拥有自主知识产权的中文维基（Wiki）系统，由互动在线（北京）科技有限公司于2006 年11月28日正式推出，力争为给国内外众多的维基（Wiki）爱好者提供一个免费、易用、功能强大的维基（Wiki）建站系统。HDwiki的推出，填补了中文维基（Wiki)的空白。"
    },
    "Lashou(拉手网)": {
        "type": ProductType.others,
        "producer": "拉手网",
        "desc": "拉手网官方站点。"
    },
    "Mojing": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "希捷NAS": {
        "type": ProductType.device,
        "producer": "希捷公司",
        "desc": "希捷（Seagate Technology Cor）成立于1979年，目前是全球最大的硬盘、磁盘和读写磁头制造商，总部位于美国加州司各特谷市。希捷在设计、制造和销售硬盘领域居全球领先地位，提供用于企业、台式电脑、移动设备和消费电子的产品。"
    },
    "v2_conference": {
        "type": ProductType.others,
        "producer": "由北京威速科技有限公司",
        "desc": "V2 Conference视频会议系统是由北京威速科技有限公司自主研发一款很成熟的网络视频会议系统。"
    },
    "WaiKuCMS(歪酷CMS)": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "Ziroom": {
        "type": ProductType.others,
        "producer": "自如",
        "desc": "自如是提供高品质居住产品与服务的互联网O2O品牌，拥有自如友家、自如整租、业主直租、自如寓、自如驿、自如民宿等产品，提供保洁、维修、搬家及优品等多项服务。"
    },
    "Spring": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": "Spring Framework是一个开源的Java／Java EE全功能栈（full-stack）的应用程序框架， 以Apache许可证形式发布，也有.NET平台上的移植版本。"
    },
    "XYCMS": {
        "type": ProductType.cms,
        "producer": "江苏鑫跃科技",
        "desc": "XYCMS企业建站系统是以asp+access进行开发的企业建站系统。"
    },
    "百奥知实验室综合信息管理系统": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "当当网": {
        "type": ProductType.others,
        "producer": "当当网",
        "desc": "当当网分站SQL注入漏洞。"
    },
    "WDS CMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "Tencent": {
        "type": ProductType.others,
        "producer": "腾讯",
        "desc": "腾讯官方站点。"
    },
    "Ecitic": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Lvmama(驴妈妈)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Misfortune": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Cyberfolio": {
        "type": ProductType.others,
        "producer": "Cyberfolio",
        "desc": None
    },
    "AzenoCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "深澜计费引擎": {
        "type": ProductType.device,
        "producer": None,
        "desc": None
    },
    "FlexCMS": {
        "type": ProductType.cms,
        "producer": "FlexCMS",
        "desc": "FlexCMS is a user-friendly website content management system.  With FlexCMS you can easily build dynamic websites within a matter of minutes with just the click of your mouse!  Maintain your web content, navigation and even limit what groups or specific users can access, from anywhere in the world with just a web browser!  With an emphasis on security and functionality, FlexCMS is a professional and robust system suitable for any business or organization website.  Built on the PHP programming language and the MySQL database, FlexCMS delivers superb performance on any size website."
    },
    "互联星空": {
        "type": ProductType.others,
        "producer": "中国电信",
        "desc": "中国电信ChinaVnet互联星空业务（以下简称“互联星空”）是中国电信在CHINAnet互联网接入层业务之上提供的互联网应用层业务。"
    },
    "清大新洋": {
        "type": ProductType.others,
        "producer": "北京清大新洋科技有限公司",
        "desc": "北京清大新洋通用图书馆系统。"
    },
    "正方教务管理系统": {
        "type": ProductType.cms,
        "producer": "杭州正方电子工程有限公司",
        "desc": "正方现代教学管理系统是一个面向学院各部门以及各层次用户的多模块综合信息管理系，包括教务公共信息维护、学生管理、师资管理、教学计划管理、智能排课、考试管理、选课管理、成绩管理、教材管理、实践管理、收费管理、教学质量评价、毕业生管理、体育管理、实验室管理以及学生综合信息查询、教师网上成绩录入等模块，能够满足从学生入学到毕业全过程及教务管理各个环节的管理需要。系统采用了当前流行的C/S结构和Internet网络技术，使整个校园网甚至Internet上的用户都可访问该系统，最大程度地实现了数据共享，深受广大用户青睐。"
    },
    "金窗教务系统": {
        "type": ProductType.cms,
        "producer": "成都金窗软件开发有限公司",
        "desc": "金窗教务系统站点。"
    },
    "McNews": {
        "type": ProductType.others,
        "producer": None,
        "desc": "mcNews是一套允许用户在WEB上张贴新闻的脚本系统，可运行在Linux和Unix操作系统上，也可运行在Microsoft Windows操作系统下。"
    },
    "ZeroCMS": {
        "type": ProductType.cms,
        "producer": "CMSZERO",
        "desc": "CMSZERO是免费开源网站内容管理系统，主要面向企业进行快速的建造简洁，高效，易用，安全的公司企业网站，一般的开发人员就能够使用本系统以最低的成本、最少的人力投入在最短的时间内架设一个功能齐全、性能优异的公司企业网站。CMSZERO是基于ASP+Access(sql2005)开发的网站内容管理系统，提供了简介类模块，新闻类模块，产品类模块，图片类模块，下载类模块。你在使用过程中可选择任意模块来建设您的网站。"
    },
    "WHMCS": {
        "type": ProductType.cms,
        "producer": "WHMCS",
        "desc": "WHMCS是一套国外流行的域名主机管理软件，跟国内众所周知的IDCSystem一样，主要在用户管理、财务管理、域名接口、服务器管理面板接口等方面设计的非常人性化。WHMCS是一套全面支持域名注册管理解析，主机开通管理，VPS开通管理和服务器管理的一站式管理软件，目前已经被越来越多的中国站长们所熟悉和了解。"
    },
    "中科院": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "金智教育CMS": {
        "type": ProductType.cms,
        "producer": "江苏金智教育信息股份有限公司",
        "desc": None
    },
    "寻医问药网": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Gobetters": {
        "type": ProductType.others,
        "producer": "北京高百特科技有限公司",
        "desc": "高百特专注于视频通讯领域，陆续推出了视频会议系统、远程培训系统、网络直播系统等视频通讯软件系统。基于大容量的系统架构设计，还能与ERP、OA、CRM等信息系统集成，做到真正的协同办公。并与相关行业结合提供各类行业的解决方案，全高清视频和高保真音质效果突破地域的限制，丰富的多媒体互动和数据共享功能让沟通更方便。"
    },
    "酷6网": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "KJ65N煤矿安全监控系统": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "KJ65N煤矿安全监控系统。"
    },
    "谷姐": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "e-Learning": {
        "type": ProductType.others,
        "producer": "广州汇思信息科技有限公司",
        "desc": None
    },
    "赶集网": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "合众商道php系统": {
        "type": ProductType.cms,
        "producer": "合众商道科技有限公司",
        "desc": "合众商道一款PHP建站系统。"
    },
    "SVN": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": None
    },
    "1Caitong(一采通)": {
        "type": ProductType.cms,
        "producer": "北京一采通信息科技有限公司",
        "desc": "一采通起源于2000年，一直致力于企业采购信息化、采购咨询领域，面向招采管理、集团集约化采购管理、精益供应链、战略采购、项目供应链、产业化服务等方向提供深度解决方案。"
    },
    "Cacti": {
        "type": ProductType.cms,
        "producer": "The Cacti Group, Inc.",
        "desc": "Cacti是一套基于PHP,MySQL,SNMP及RRDTool开发的网络流量监测图形分析工具。"
    },
    "Csgi": {
        "type": ProductType.others,
        "producer": "CAUCHO",
        "desc": "Resin是CAUCHO公司的产品，是一个非常流行的支持servlets和jsp的引擎，速度非常快。Resin本身包含了一个支持HTTP/1.1的WEB服务器。它不仅可以显示动态内容，而且它显示静态内容的能力也非常强，速度直逼APACHESERVER。许多站点都是使用该WEB服务器构建的。"
    },
    "Drupal": {
        "type": ProductType.cms,
        "producer": "Drupal ",
        "desc": "Drupal 是一个自由和开源的模块化框架和内容管理系统，用PHP语言写成。它也被称为内容管理框架，因为其功能已经超越了一般意义上的内容系统。Drupal可以运行在Windows和Unix/Linux操作系统上，支持IIS和Apache Web服务器，需要MySQL或者PostgreSQL数据库。"
    },
    "航空公司官方站点": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "MunkyScripts": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": None
    },
    "PPTV": {
        "type": ProductType.others,
        "producer": "Pptv",
        "desc": "Pptv官方站点。"
    },
    "Oppein": {
        "type": ProductType.others,
        "producer": "欧派家居集团股份有限公司",
        "desc": "欧派家居集团股份有限公司官方站点。"
    },
    "Enorth Webpublisher CMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "Enorth Webpublisher是网络媒体内容管理、发布平台。"
    },
    "Limbo CMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": " Limbo CMS 中文版 一个基于TXT,SQLite,MYSQL数据库结构的PHP网站内容管理系统，可以简易快捷的迅速建立一个PHP动态智能网站。"
    },
    "DouPHP": {
        "type": ProductType.cms,
        "producer": "漳州豆壳网络科技有限公司",
        "desc": "DouPHP 是一款轻量级企业网站管理系统，基于PHP+Mysql架构的，可运行在Linux、Windows、MacOSX、Solaris等各种平台上，系统搭载Smarty模板引擎，支持自定义伪静态，前台模板采用DIV+CSS设计，后台界面设计简洁明了，功能简单易具有良好的用户体验，稳定性好、扩展性及安全性强，可面向中小型站点提供网站建设解决方案。"
    },
    "政府某通用CMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "AfterLogic WebMail": {
        "type": ProductType.cms,
        "producer": "Afterlogic Corp.",
        "desc": "AfterLogic WebMail Lite是一个快速易于使用的Webmail前台系统，支持 POP3/IMAP账号，SMTP和SSL（包括Gmail）。拥有一个漂亮的Ajax界面。 "
    },
    "中科新业网络哨兵": {
        "type": ProductType.device,
        "producer": "中科新业公司",
        "desc": "中科新业网络哨兵——互联网安全审计系统是中科新业公司自主开发，集行为审计与内容审计为一体，以旁路的方式部署在网络出口。通过优化的网络数据获取技术、专门细致的协议分析技术、数据存储技术、数据查询技术、并配合完善分类的URL过滤库网址和管理规则，帮助用户应对来自互联网的风险和挑战。是一款安全、高效、易于管理和扩展的网络安全产品。"
    },
    "金盘非书资料管理系统": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "VisionSoft": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "息壤": {
        "type": ProductType.others,
        "producer": "息壤",
        "desc": "息壤始建于 2003 年，是国内技术领先的知名网络服务提供商 , 专注于互联网基础应用服务，具有因特网信息服务 ICP 和因特网接入服务运营商 ISP 双重资质的专业企业。"
    },
    "宝钢集团": {
        "type": ProductType.others,
        "producer": "宝钢集团",
        "desc": None
    },
    "Jetty Web Server": {
        "type": ProductType.os,
        "producer": None,
        "desc": None
    },
    "MaticsoftSNS": {
        "type": ProductType.middleware,
        "producer": "动软卓越（北京）科技有限公司",
        "desc": "动软分享社区系统，是一套专业社会化电子商务分享社区解决方案，包括微博动态、图片、商品及视频等内容分享的购物分享社区系统。"
    },
    "宝信": {
        "type": ProductType.others,
        "producer": "宝信软件",
        "desc": "宝信软件在推动信息化与工业化深度融合、支撑中国制造企业发展方式转变、提升城市智能化水平等方面作出了突出的贡献，成为中国领先的工业软件行业应用解决方案和服务提供商。公司产品与服务业绩遍及钢铁、交通、医药、有色、化工、装备制造、金融、公共服务、水利水务等多个行业。"
    },
    "移商网": {
        "type": ProductType.others,
        "producer": "移商网集团",
        "desc": "移商网集团是享受深圳市政府专项资金扶持的高新技术企业。位于集高新技术的研发、高新技术企业的孵化、创新人才的吸纳与培育于一体的国家级大学科技园-深圳市南山科技园比克科技大厦（腾讯大厦旁），是国内首家移动技术方案平台提供商。"
    },
    "ACSNO(埃森诺)": {
        "type": ProductType.others,
        "producer": "沈阳埃森诺信息技术股份有限公司",
        "desc": "埃森诺网络质量监测系统"
    },
    "Lvmaque(绿麻雀)": {
        "type": ProductType.cms,
        "producer": "绿麻雀（北京）科技有限公司",
        "desc": "绿麻雀是一款专业的p2p借贷系统，并且提供p2p网贷平台的全方位技术支持和网站运营策划，拥有一支高素质，高学历的技术管理团队，都是来自IT前沿，拥有高超的技术和丰富的制作经验。能为客户提供稳定，高效的服务以及解决问题的最佳方案。"
    },
    "D-Link": {
        "type": ProductType.device,
        "producer": None,
        "desc": None
    },
    "FlatNuke": {
        "type": ProductType.cms,
        "producer": "FlatNuke",
        "desc": "FlatNuke是一个PHP开发的内容管理系统，无须数据库支持，使用的是文本文件来保存内容。"
    },
    "ImagineCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "磊科路由器": {
        "type": ProductType.device,
        "producer": "深圳市磊科实业有限公司",
        "desc": "磊科路由器。"
    },
    "OurPHP(傲派软件)": {
        "type": ProductType.cms,
        "producer": "哈尔滨伟成科技有限公司",
        "desc": "OURPHP是一个品牌,一款基于PHP+MySQL开发符合W3C标准的建站系统。"
    },
    "绍兴深蓝软件": {
        "type": ProductType.others,
        "producer": "绍兴深蓝软件公司",
        "desc": "以建设行业电脑应用管理为主导产品，辅以电子商务、办公自动化、房产、档案管理、智能卡应用等系列软件。几年来，绍兴深蓝软件公司不断引进国际先进的软件开发管理平台，融合领先的电子商务技术和国际先进的管理思想，使产品不断丰富完善。"
    },
    "CSDN": {
        "type": ProductType.others,
        "producer": "CSDN",
        "desc": "CSDN官方网站。"
    },
    "Amigo(金立)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "LotusCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "LotusCMS was an early experiment of myself learning PHP, with initial first non-public versions being written in 2007/2008."
    },
    "Dream4 Koobi CMS": {
        "type": ProductType.cms,
        "producer": " Koobi CMS",
        "desc": "Koobi 是基于互联网的软件, 它不需要您懂HTML知识或其他编成知识，例如新闻, 文章, 登入, 下载, 图库, 调查等等都能被管理者很好的管理。 Koobi 是基于互联网技术的, 信息将通过浏览器(例如 Internet Explorer 、Firefox 或 Netscape) 被很好地表现。"
    },
    "超星网": {
        "type": ProductType.others,
        "producer": "超星网",
        "desc": "超星网分站存在远程文件包漏洞。"
    },
    "宝利通": {
        "type": ProductType.others,
        "producer": "宝利通",
        "desc": "宝利通是专业开发、制造和销售高质量音视频会议系统及解决方案的领先提供商。通过最广泛地整合视频、语音、数据和网络解决方案提供最佳通讯体验。"
    },
    "TRS WCM(拓尔思内容协作平台)": {
        "type": ProductType.cms,
        "producer": "北京拓尔思信息技术股份有限公司",
        "desc": "TRS Web Content Management( TRS WCM ), 是-套完全基于Java和浏览器技术的网络内容管理软件。"
    },
    "CmsEasy": {
        "type": ProductType.cms,
        "producer": "四平市九州易通科技有限公司",
        "desc": "是一款基于 PHP+Mysql 架构的网站内容管理系统，也是一个 PHP 开发平台。 采用模块化方式开发，功能易用便于扩展，可面向大中型站点提供重量级网站建设解决方案。"
    },
    "Hr163": {
        "type": ProductType.others,
        "producer": "网易",
        "desc": "网易hr站点。"
    },
    "Info_Robots": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "RocKontrol": {
        "type": ProductType.others,
        "producer": "罗克佳华",
        "desc": "罗克佳华，中外合资的高科技企业，信息化和自动化的总承包商，是集产学研为一体的科研生产型企业，专注于用信息化手段推进安全生产、环境治理、节能减排、金融监控，保证管理体系监管有力。"
    },
    "东方电子SCADA": {
        "type": ProductType.others,
        "producer": "东方电子集团有限公司",
        "desc": "东方电子SCADA通用系统站点。"
    },
    "北京大学": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "OSA": {
        "type": ProductType.others,
        "producer": None,
        "desc": "osa，全名：Open Service Architecture，是3GPP组织提出的用于快速部署业务的开放业务平台。"
    },
    "安达通安全网关": {
        "type": ProductType.device,
        "producer": "上海安达通",
        "desc": "上海安达通安全网关。"
    },
    "Synjones": {
        "type": ProductType.cms,
        "producer": "新中新集团",
        "desc": "新中新是国内领先的校园一卡通系统等解决方案供应商,在智能一卡通系统及智能交通系统领域拥有多年的技术优势与经验积累,业务涵盖智慧校园,智慧交通,智慧公安,智慧园区等"
    },
    "体验宝": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "ThaiWeb": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Wiznote": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "BugFree": {
        "type": ProductType.cms,
        "producer": "BugFree",
        "desc": "BugFree是借鉴微软的研发流程和Bug管理理念，使用PHP+MySQL独立写出的一个Bug管理 系统。简单实用、免费并且开放源代码(遵循GNU GPL)。 命名BugFree 有两层意思：一是希望软件中的缺陷越来越少直到没有，Free嘛；二是表示它是免费且开放源代码的，大家可以自由使用传播。"
    },
    "DianYiPS建站系统": {
        "type": ProductType.cms,
        "producer": "DianYiPS",
        "desc": "DianYiPS建站系统"
    },
    "Midea": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "U193": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "DaMall": {
        "type": ProductType.cms,
        "producer": "成都网亚科技有限公司",
        "desc": "DaMall商城系统。"
    },
    "铱迅web应用防护系统": {
        "type": ProductType.device,
        "producer": "南京铱迅信息技术有限公司",
        "desc": "铱迅Web应用防护系统（也称：铱迅网站应用级入侵防御系统，英文：Yxlink Web Application Firewall，简称：Yxlink WAF）是铱迅信息结合多年在应用安全理论与应急响应实践经验积累的基础上，自主研发的一款应用级防护系统。在提供Web应用实时深度防御的同时，实现Web应用加速与防止敏感信息泄露的功能，为Web应用提供全方位的防护解决方案。\n产品致力于解决应用及业务逻辑层面的安全问题，广泛适用于“政府、金融、运营商、公安、能源、税务、工商、社保、交通、卫生、教育、电子商务”等所有涉及Web应用的各个行业。部署铱迅Web应用防护系统，可以帮助用户解决目前所面临的各类网站安全问题，如：注入攻击、跨站攻击、脚本木马、缓冲区溢出、信息泄露、应用层CC攻击、DDoS攻击等常见及最新的安全问题。"
    },
    "Microsoft": {
        "type": ProductType.os,
        "producer": "Microsoft",
        "desc": None
    },
    "EkuCMS(易酷CMS)": {
        "type": ProductType.cms,
        "producer": "易酷CMS",
        "desc": "易酷CMS是支持Windows/Linux/PHP+MySql环境的ZIP格式软件，以开源、免费、功能强大、安全健壮、性能卓越、超级易用、模板众多、插件齐全等优势，受到众多企业和站长的喜爱。"
    },
    "JBoss": {
        "type": ProductType.middleware,
        "producer": "红帽公司",
        "desc": "Jboss是一个基于J2EE的开放源代码的应用服务器。 JBoss代码遵循LGPL许可，可以在任何商业应用中免费使用。JBoss是一个管理EJB的容器和服务器，支持EJB 1.1、EJB 2.0和EJB3的规范。但JBoss核心服务不包括支持servlet/JSP的WEB容器，一般与Tomcat或Jetty绑定使用。"
    },
    "重庆邮电大学": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "MyABraCaDaWeb": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "ecoCMS": {
        "type": ProductType.cms,
        "producer": "北京易科势腾科技股份有限公司",
        "desc": "Ecocms内容管理系统站点。"
    },
    "UWA": {
        "type": ProductType.others,
        "producer": None,
        "desc": "UWA为一款通用建站系统。"
    },
    "ALLWIF": {
        "type": ProductType.device,
        "producer": None,
        "desc": None
    },
    "Gizzar": {
        "type": ProductType.database,
        "producer": None,
        "desc": None
    },
    "北京中农信达": {
        "type": ProductType.others,
        "producer": "北京中农信达",
        "desc": "中农信达农村集体三资网络监管系统。"
    },
    "HPCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "Gykghn": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Smarty3": {
        "type": ProductType.middleware,
        "producer": None,
        "desc": "marty是一个使用PHP写出来的模板PHP模板引擎，它提供了逻辑与外在内容的分离，简单的讲，目的就是要使用PHP程序员同美工分离,使用的程序员改变程序的逻辑内容不会影响到美工的页面设计。"
    },
    "联想": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Java RMI": {
        "type": ProductType.middleware,
        "producer": "Oracle",
        "desc": "RMI(Remote Method Invocation，远程方法调用)是用Java在JDK1.2中实现的，它大大增强了Java开发分布式应用的能力。Java作为一种风靡一时的网络开发语言，其巨大的威力就体现在它强大的开发分布式网络应用的能力上，而RMI就是开发百分之百纯Java的网络分布式应用系统的核心解决方案之一。"
    },
    "JiaoTong(交通公众出行)": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "PHPWind": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "phpwind（简称：pw）是一个基于PHP和MySQL的开源社区程序，是国内最受欢迎的通用型论坛程序之一。"
    },
    "京东": {
        "type": ProductType.others,
        "producer": "京东",
        "desc": "京东官方站点。"
    },
    "AiJiaCMS(爱家CMS)": {
        "type": ProductType.cms,
        "producer": "南充市爱佳网络有限公司",
        "desc": "AiJiaCMS爱家房产门户系统。"
    },
    "Baidu": {
        "type": ProductType.others,
        "producer": "百度",
        "desc": None
    },
    "三福百货": {
        "type": ProductType.others,
        "producer": "三福百货有限公司",
        "desc": "三福百货有限公司官方站点。"
    },
    "Kuwo(酷我)": {
        "type": ProductType.cms,
        "producer": "酷我",
        "desc": "酷我官方站点。"
    },
    "珠海高凌环境监测系统": {
        "type": ProductType.others,
        "producer": "珠海高凌信息科技股份有限公司",
        "desc": "环境噪声自动监测系统由噪声监测终端（NGL04 ENS）、通讯网络及监控中心组成。现场监测终端可扩展气象及车流量终端等，现场监测终端通过多种通讯方式与监控中心交互数据，监控中心通过噪声系统软件（V3.0版）对噪声数据进行统计分析处理。系统具有无人值守、全天候连续运行、安装部署快捷、运行维护简单等特点，是专用于户外长期使用的噪声自动监测系统，为各城市建设安静和谐环境提供了及时、准确的噪声监测数据，为声环境评价和治理提供了有效可靠的依据。"
    },
    "Tenpay(财付通)": {
        "type": ProductType.others,
        "producer": "腾讯",
        "desc": "理财通是腾讯官方理财平台，为用户提供多样化的理财服务。精选货币基金、保险理财、指数基金等多款理财产品。可官网、微信、手机QQ三平台灵活操作，随时随地无缝理财。"
    },
    "优酷网": {
        "type": ProductType.others,
        "producer": "阿里巴巴文化娱乐集团",
        "desc": "优酷由古永锵在2006年6月21日创立，优酷现为阿里巴巴文化娱乐集团大优酷事业群下的视频平台。"
    },
    "AnyMacro Mail邮件系统": {
        "type": ProductType.cms,
        "producer": "北京安宁创新网络科技股份有限公司",
        "desc": "Anymacro Mail System 是基于统一消息架构上的系统，具备良好的伸缩性，可以支持从数千到上千万用户数量，具有非常高的稳定性、可扩展性。在可靠性、安全性和中文支持、病毒查杀、反垃圾、灵活过滤、消息集成、界面表现力等关键特征上安宁系统具有领先的优势。"
    },
    "DOSSM(广州问途网络营销系统)": {
        "type": ProductType.cms,
        "producer": "广州问途",
        "desc": "广州问途网络营销系统站点。"
    },
    "银泰集团": {
        "type": ProductType.others,
        "producer": "中国银泰投资有限公司",
        "desc": "银泰集团（全称“中国银泰投资有限公司”）由沈国军先生于1997年在北京创立，是一家多元化产业投资集团，下辖银泰商业集团、银泰置地集团、银泰资源集团、银泰旅游产业集团、银泰投资与金融集团，拥有多家境内外上市公司和100 多家控股、参股公司。目前银泰集团已创造了十万多个就业岗位，已成为在中国最具实力的民营企业之一。"
    },
    "Discuz!": {
        "type": ProductType.cms,
        "producer": "北京康盛新创科技有限责任公司",
        "desc": "Crossday Discuz! Board 论坛系统（简称 Discuz! 论坛）是一个采用 PHP 和 MySQL 等其他多种数据库构建的高效论坛解决方案 Discuz! 在代码质量，运行效率，负载能力，安全等级，功能可操控性和权限严密性等方面都在广大用户中有良好的口碑。"
    },
    "春秋航空": {
        "type": ProductType.others,
        "producer": "春秋航空",
        "desc": "春秋航空分站存在远程文件包含。"
    },
    "ZCNCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "FotoWeb": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "暴风魔镜": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "中国银行": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "网康应用安全网关": {
        "type": ProductType.device,
        "producer": "网康科技",
        "desc": "网康应用安全网关产品NS-ASG(Netentsec Application Security Gateway)是网康科技根据丰厚网应用管理经验，面向目前企业应用系统集中化、“云”端化以及用户终端移动化等特点而推出的一款集IPSec功能于一体的二合一SSL VPN产品。该产品旨在为企业用户提供一种企业内部应用的简便的，可靠的，安全的访问手段，并且，对于应用本身是直观的，可视的方式，不要求企业管理员进行复杂的网络管理。NS-ASG产品结合了IPSec和SSL两大主流VPN功能的优势，完美地解决了单一的IPSec VPN或者SSL VPN设备在实际应用中存在的问题；并且，该产品也可以为企业私有云应用提供安全可靠的访问保障。"
    },
    "湖州人才网": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "P2P通用系统": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "华创证券": {
        "type": ProductType.others,
        "producer": "华创证券",
        "desc": "华创证券官方站点。"
    },
    "Ecmall": {
        "type": ProductType.cms,
        "producer": "上海商派网络科技有限公司",
        "desc": "ECMall 社区电子商务系统(简称ECMall)是上海商派网络科技有限公司继ECShop 之后推出的又一个电子商务姊妹产品。与 ECShop 不同的是，ECMall 是一个允许店铺加盟的多店系统。它不仅可以帮助众多成熟的网络社区实现社区电子商务还可以推进各种地域性、垂直性明显的门户网站的电子商务进程。 ECMall是一个根据融合了电子商务以及网络社区特色的产品，它不仅能使您的电子商务进程变得异常轻松，同时通过和康盛创想相关产品的结合还能进一步提高用户的活跃度以及黏性，从而促进用户的忠诚度。"
    },
    "金盘图书馆系统": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "擎天政务系统": {
        "type": ProductType.cms,
        "producer": "南京擎天科技有限公司",
        "desc": "擎天政务系统"
    },
    "1039JXT(1039家校通)": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "1039家校通是一套专针对学生、教师、家长互动的一套系统，主要功能有班主任可以给自己本班所有学生和部分学生发送通知和信息，年级组可给本校所有教工发送通知和信息，并且学生在校园的家校通终端上刷卡时，家长就能收到自己学生的到、离校的短信。 "
    },
    "Douban(豆瓣)": {
        "type": ProductType.others,
        "producer": "豆瓣",
        "desc": "豆瓣网站任意url跳转。"
    },
    "ASUS Router": {
        "type": ProductType.device,
        "producer": "华硕",
        "desc": "华硕路由器。"
    },
    "伊利": {
        "type": ProductType.others,
        "producer": "内蒙古伊利实业集团股份有限公司",
        "desc": "伊利是中国符合奥运会标准，为2008年北京奥运会提供服务的乳制品企业。"
    },
    "360游戏中心": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "CmsTop": {
        "type": ProductType.cms,
        "producer": "CmsTop",
        "desc": "CMSTOP是一款网站内容管理系统（CMS），主要服务于网络媒体、报业、杂志、广电、政府和大中型企业等，目前已服务了超过百家知名媒体网站。"
    },
    "人人网": {
        "type": ProductType.others,
        "producer": "人人网",
        "desc": "人人网官方站点。"
    },
    "FineCMS": {
        "type": ProductType.cms,
        "producer": "FineCMS",
        "desc": "FineCMS是一款基于PHP+MySql开发的内容管理系统，采用MVC设计模式实现业务逻辑与表现层的适当分离，使网页设计师能够轻松设计出理想的模板，插件化方式开发功能易用便于扩展，支持自定义内容模型和会员模型，并且可以自定义字段，系统内置文章、图片、下载、房产、商品内容模型，系统表单功能可轻松扩展出留言、报名、书籍等功能，实现与内容模型、会员模型相关联，FineCMS可面向中小型站点提供重量级网站建设解决方案。"
    },
    "M1905": {
        "type": ProductType.others,
        "producer": "一九零五（北京）网络科技有限公司",
        "desc": "m1905电影网是国家广播电影电视总局电影卫星频道节目制作中心（CCTV-6，简称：电影频道）投资建立的电影行业门户网站。"
    },
    "锐捷网络": {
        "type": ProductType.device,
        "producer": "锐捷",
        "desc": "锐捷网络设备。"
    },
    "KXmail": {
        "type": ProductType.cms,
        "producer": "成都科信科技有限公司",
        "desc": "KXmail邮件系统是科信软件公司十年潜心研发的结晶，该系统可运行在Windows、Linux、Unix等操作系统平台，并且支持 Oracle、Mysql、Sybase、MSSQL、DB2等数据库，邮件管理和存储都非常方便和快捷。"
    },
    "AcSoft": {
        "type": ProductType.others,
        "producer": "杭州安财软件有限公司",
        "desc": "系统基于.net开发平台，采用Web service进行远程数据封装和多线程数据处理技术；WEB浏览器方式，多层结构设计，分布式数据管理，支持SQL server 2000/ SQL server 2005/ SQL server 2008；CA数字认证，集中式的管理，灵活的用户接口。"
    },
    "Youku(优酷)": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "圆通": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "教育云公共服务平台系统": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "山东鲁能教育云公共服务平台系统。"
    },
    "Dangdang": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Xplus": {
        "type": ProductType.others,
        "producer": "新数通盛世科技（北京）有限公司",
        "desc": "Xplus是新数通盛世科技（北京）有限公司旗下的一家数字媒体发行平台。"
    },
    "铁威马NAS网络存储服务器": {
        "type": ProductType.device,
        "producer": "铁马威",
        "desc": "铁威马NAS网络存储服务器。"
    },
    "Tomcat": {
        "type": ProductType.middleware,
        "producer": "Apache 软件基金会",
        "desc": "Tomcat是Apache 软件基金会（Apache Software Foundation）的Jakarta 项目中的一个核心项目，由Apache、Sun 和其他一些公司及个人共同开发而成。由于有了Sun 的参与和支持，最新的Servlet 和JSP 规范总是能在Tomcat 中得到体现，Tomcat 5支持最新的Servlet 2.4 和JSP 2.0 规范。因为Tomcat 技术先进、性能稳定，而且免费，因而深受Java 爱好者的喜爱并得到了部分软件开发商的认可，成为目前比较流行的Web 应用服务器。"
    },
    "天涯": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "TCExam": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "TCExam 是一款基于网络的开源在线考试系统，用于在线试题的生成、管理等方面。"
    },
    "Hsort": {
        "type": ProductType.others,
        "producer": "北京水天科技有限公司",
        "desc": "hsort数字报刊管理系统"
    },
    "WebsiteBakerCMS": {
        "type": ProductType.cms,
        "producer": "WebsiteBaker Org",
        "desc": "WebsiteBaker可帮助您创建所需的网站：免费，简单，安全，灵活且可扩展的开源内容管理系统（CMS）。"
    },
    "eFuture": {
        "type": ProductType.others,
        "producer": "北京富基融通科技有限公司",
        "desc": "efuture，富基融通，开发的高流动性解决方案群，致力于帮助客户改善流通基因，成就在“客户流、订单流、物流、资金流和信息流”等五大流通河流的高流动性，实践证明这些方案群已经帮助我们的客户赢得了可持续发展的竞争优势。"
    },
    "NpMaker": {
        "type": ProductType.others,
        "producer": None,
        "desc": "NpMaker是一款实现传统报纸到数字报纸转化的实用工具，名称由Newspaper Maker（报纸制作器）缩写而来。NpMaker产品整体包括此转化工具软件、一套数字报纸发布系统以及一套报纸管理后台系统。"
    },
    "Workyi人才系统": {
        "type": ProductType.others,
        "producer": "工作易人才系统",
        "desc": "基于Asp.Net+MsSQL的开源高端人才系统,人才招聘程序.为创业者带来低投入高回报的人才系统。"
    },
    "北京心海通用型管理系统": {
        "type": ProductType.cms,
        "producer": "北京心海",
        "desc": "北京心海通用型管理系统"
    },
    "HttpFileServer": {
        "type": ProductType.device,
        "producer": None,
        "desc": "Http File Server是专为个人用户所设计的 HTTP文件服务器，如果您觉得架设 FTPServer太麻烦，那么这个软件可以提供您更方便的档案传输系统，下载后无须安装。"
    },
    "Juniper": {
        "type": ProductType.device,
        "producer": "Juniper",
        "desc": "Juniper网络设备。"
    },
    "Tipask": {
        "type": ProductType.cms,
        "producer": "北京造极登峰科技有限公司",
        "desc": "tipask，即Tipask问答系统，是一款开放源码的PHP仿百度知道程序。"
    },
    "FengCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "人民网": {
        "type": ProductType.others,
        "producer": "人民问答",
        "desc": None
    },
    "中國港中旅集團": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Foxitsoftware(福昕)": {
        "type": ProductType.others,
        "producer": "福建福昕软件开发股份有限公司 ",
        "desc": "福昕软件主站。"
    },
    "Cclinux": {
        "type": ProductType.cms,
        "producer": None,
        "desc": None
    },
    "B2Bbuilder": {
        "type": ProductType.cms,
        "producer": "远丰集团",
        "desc": "B2Bbuilder是一款基于PHP+MySQL的开源B2B电子商务行业门户网站解决方案，利用B2Bbuilder可以快速部署建立一个功能强大的B2B电子商务行业网站，或地方门户网站。B2Bbuilder也是目前国内用户最多，功能齐全，性能好，最易使用的B2B系统，也是唯一家支持多语言版本的软件系统。"
    },
    "全球眼监控": {
        "type": ProductType.device,
        "producer": None,
        "desc": "“全球眼”网络视频监控业务，是由中国电信推出的一项完全基于宽带网的图像远程监控、传输、存储、管理的增值业务。"
    },
    "Windows": {
        "type": ProductType.os,
        "producer": "Microsoft ",
        "desc": "Microsoft Windows（中文有时译作微软视窗，通常不做翻译）是微软公司推出的一系列操作系统。它问世于1985年，起初是MS-DOS之下的桌面环境，其后续版本逐渐发展成为主要为个人计算机和服务器用户设计的操作系统，并最终获得了世界个人计算机操作系统的垄断地位。此操作系统可以在几种不同类型的平台上运行，如个人计算机（PC）、移动设备、服务器（Server）和嵌入式系统等等，其中在个人计算机的领域应用内最为普遍。"
    },
    "管家婆ECT": {
        "type": ProductType.cms,
        "producer": "任我行软件股份有限公司",
        "desc": "任我行ECT(Enterprise Control Tools)，是先进运营管理方法和信息化工具的完美结合。该系统已成功应用于大量客户，它是以“客户”为中心，以“销售团队管理”为核心，以提升流程与执行力为诉求的企业级“管人管事执行管控工具”。"
    },
    "Mainone": {
        "type": ProductType.cms,
        "producer": "北京铭万智达科技有限公司",
        "desc": "北京铭万智达科技有限公司作为中国领先的中小企业互联网服务商，为中小企业提供商业搜索、企业云端建站、大数据网络营销、移动互联网应用、垂直B2B电子商务、高端定制等服务。"
    },
    "Mambo": {
        "type": ProductType.others,
        "producer": None,
        "desc": "mambo是一个基于php+mysql的开放源码的网站内容管理系统（CMS），具有强大的功能、友好的后台管理界面。是建立中小型站点的绝佳选择。"
    },
    "Weiphp": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "Zabbix": {
        "type": ProductType.middleware,
        "producer": "Zabbix LLC",
        "desc": "Zabbix 是由 Alexei Vladishev 开发的一种网络监视、管理系统，基于 Server-Client 架构。可用于监视各种网络服务、服务器和网络机器等状态。\nZabbix 使用 MySQL、PostgreSQL、SQLite、Oracle 或 IBM DB2 储存资料。Server 端基于 C语言、Web 前端则是基于 PHP 所制作的。Zabbix 可以使用多种方式监视。可以只使用 Simple Check 不需要安装 Client 端，亦可基于 SMTP 或 HTTP 等各种协定做死活监视。在客户端如 UNIX、Windows 中安装 Zabbix Agent 之后，可监视 CPU 负荷、网络使用状况、硬盘容量等各种状态。而就算没有安装 Agent 在监视对象中，Zabbix 也可以经由 SNMP、TCP、ICMP检查，以及利用 IPMI、SSH、telnet 对目标进行监视。另外，Zabbix 包含 XMPP 等各种 Item 警示功能。"
    },
    "XAMPP": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "XAMPP（Apache+MySQL+PHP+PERL）是一个功能强大的建站集成软件包。这个软件包原来的名字是 LAMPP，但是为了避免误解，最新的几个版本就改名为 XAMPP 了。它可以在Windows、Linux、Solaris、Mac OS X 等多种操作系统下安装使用，支持多语言：英文、简体中文、繁体中文、韩文、俄文、日文等。"
    },
    "天融信应用安全网关": {
        "type": ProductType.device,
        "producer": "天融信",
        "desc": "天融信安全网关TopGate UTM是天融信公司自主 研发的一款多功能综合应用网关产品，该产品采用的是高性能的全并行多核处理器，集合了防火墙、虚拟专用网（VPN）、入侵检测和防御（IPS）、网关防病毒、Web内容过滤、反垃圾邮件、流量整形、用户身份认证、审计以及BT、IM控制等多种应用于一身。"
    },
    "雷蛇": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "清华紫光硬件防火墙": {
        "type": ProductType.device,
        "producer": "清华紫光",
        "desc": "清华紫光硬件防火墙。"
    },
    "迈外迪wifi": {
        "type": ProductType.device,
        "producer": "上海迈外迪科技",
        "desc": "迈外迪致力于通过创新性的产品和商业模式，提升中国咖啡厅Wi-Fi应用的水平。通过将迈外迪自主专利Wi-Fi路由器安装于咖啡厅现有有线网络上，在对现有网络最小改动的基础上，实现咖啡厅Wi-Fi网络从简单的直接连接、直接上网的模式，升级到提供包括的用户认证、品牌传播、营销推广的企业专用Wi-Fi网络。"
    },
    "JASmine": {
        "type": ProductType.others,
        "producer": None,
        "desc": "Jasmine是一个Javascript的BDD（Behavior-Driven Development）测试框架，不依赖任何其他框架。"
    },
    "hf0760": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "iKuai(爱快系统)": {
        "type": ProductType.device,
        "producer": "全讯汇聚网络科技（北京）有限公司",
        "desc": "爱快系统在专注于研发具有自主知识产权的DPI七层流控网关、路由器、AP等系列产品的同时，研发了先进的DPI七层流控技术、云平台集中管理技术、Portal认证技术、以及2300+每周更新的协议应用等100多项核心功能技术。公司不仅仅提供无线组网产品和服务，同时还提供、专业、智能的流控系统、完善、便利的云平台管理系统以及多场景、多方式的Portal认证系统。"
    },
    "BlueCMS": {
        "type": ProductType.cms,
        "producer": "BlueCMS",
        "desc": "BlueCMS(地方分类信息门户专用CMS系统) 基于当今最流行的开源组合PHP＋MYSQL开发 每个分类均可单独设置Title、Keywords、Description，方便SEO 强力模板引擎，显示风格自由定义，随心所欲 多功能模块插件，操作简单方便 智能缓存技术，提高网站性能 多属性模型自定义，栏目功能强大。"
    },
    "人民问答": {
        "type": ProductType.others,
        "producer": "人民网",
        "desc": "人民网官方站点。"
    },
    "通达OA系统": {
        "type": ProductType.cms,
        "producer": "北京通达信科科技有限公司",
        "desc": "通达OA采用领先的B/S(浏览器/服务器)操作方式，使得网络办公不受地域限。Office Anywhere采用基于WEB的企业计算，主HTTP服务器采用了世界上最先进的Apache服务器，性能稳定可靠。数据存取集中控制，避免了数据泄漏的可能。提供数据备份工具，保护系统数据安全。多级的权限控制，完善的密码验证与登录验证机制更加强了系统安全性。"
    },
    "Banksys": {
        "type": ProductType.others,
        "producer": None,
        "desc": None
    },
    "FrogCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "Frog CMS是软件开发者Philippe Archambault所研发的一套内容管理系统（CMS）。该系统提供页面模板、用户权限管理以及文件管理所需的工具。"
    },
    "GxlCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "GxlcmsQY系统是针对企业用户量身打造的一款快速搭建网站的cms。"
    },
    "WuZhiCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "WUZHI CMS是中国五指（WUZHI）互联科技公司的一套基于PHP和MySQL的开源内容管理系统（CMS）"
    },
    "EasyCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "EasyCMS是一套使用PHP语言编写的、轻量级可扩展的开源内容管理系统（CMS）。"
    },
    "joyplus-cms": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "joyplus-cms（悦视频）是一套基于PHP和MySQL的开源视频后台管理系统。该系统具有视频资源采集、用户反馈管理、地址自动解析和消息推送管理等功能。 "
    },
    "Dripal avatar_uploader": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "avatar_uploader是Drupal社区所维护的一套内容管理系统中的用于实现上传用户图片功能的模块。 "
    },
    "BeayAdmin": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "BearAdmin是一套基于ThinkPHP5和AdminLTE的后台管理系统。 "
    },
    "GreenCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "GreenCMS是一套基于ThinkPHP开发的内容管理系统（CMS）。"
    },
    "CMSMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "CMS Made Simple(简称CMSMS)是一款优秀的轻量级开源内容管理系统(CMS)。"
    },
    'WolfCMS': {
        "type": ProductType.cms,
        "producer": None,
        "desc": "Wolf CMS是Wolf CMS团队开发的一套基于PHP的开源内容管理系统（CMS）。该系统提供用户界面、模板、用户管理和权限管理等功能。 "
    },
    "CraftedWeb": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "CraftedWeb是一套游戏服务器的CMS（内容管理系统）。"
    },
    "OneFileCMS": {
        "type": ProductType.cms,
        "producer": None,
        "desc": "OneFileCMS是一款只有一个文件的轻量级CMS系统。"
    }
}
