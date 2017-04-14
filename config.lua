-- http-guard安装目录，修改为实际安装到的目录。
baseDir = '/data/www/waf/'

-- 白名单
local ipSE360 = {"101.226.166.195-101.226.166.255", "101.226.167.195-101.226.167.254", "101.226.168.195-101.226.168.254", "101.226.169.195-101.226.169.230", "169.254.95.120", "180.153.227.104-180.153.227.108", "180.153.231.56-180.153.231.113", "180.153.236.1-180.153.236.255", "182.118.20.201-182.118.20.254", "182.118.21.200-182.118.21.254", "182.118.22.141-182.118.22.250", "182.118.25.1-182.118.25.254", "182.118.29.147-182.118.29.150", "182.118.35.11-182.118.35.30", "42.236.99.1-42.236.99.254"}
--local ipInner = {"127.0.0.0-127.255.255.255","192.168.1.0-192.168.1.255","172.16.0.0-172.31.255.255","10.0.0.0-10.255.255.255"}
local ipInner = {"127.0.0.0-127.255.255.255","192.168.1.0-192.168.1.255","172.16.0.0-172.31.255.255","10.0.0.0-10.28.11.78", "10.28.11.80-10.255.255.255"}
local officeIp = {"183.214.86.130", "183.214.87.30", "220.168.85.64", "220.168.85.70", "175.11.68.0-175.11.71.255"}
local ipWhitelist = {ipInner, ipSE360, officeIp}

-- 黑名单
local proxyIp = {"124.88.67.20", "124.88.67.23", "124.88.67.52"}
local fakeSE = {"124.88.67.13"}
--local blackTest = {"10.28.11.79"}
local ipBlacklist = {proxyIp, fakeSE}

-- url-protect
local urls = {[[\.php$]], [[\.html$]]}


local Config = {
	-- key是否动态生成,可选static,dynamic,如果选dynamic,下面所有的keySecret不需要更改,如果选static,修改手动修改下面的keySecret
	keyDefine = "dynamic",

	-- 被动防御,限制请求模块。根据在一定时间内统计到的请求次数作限制,建议始终开启
	-- state : 为此模块的状态，表示开启或关闭，可选值为On或Off;
	-- maxReqs，amongTime : 在amongTime秒内允许请求的最大次数maxReqs，如默认的是在10s内最大允许请求50次。
	-- urlProtect : 指定限制请求次数的url正则表达式文件，默认值为\.php$，表示只限制php的请求(当然，当urlMatchMode = "uri"时，此正则才能起作用)
	limitReqModules = { state = true , maxReqs = 20 , amongTime = 120, urlProtect = urls },

	-- 用于当输入验证码验证通过时,生成key的密码.如果上面的keyDefine为dynamic，就不需要修改
	captchaKey = "K4QEaHjwyF",

	-- 值为captcha时,表示ip在黑名单后返回带有验证码的页面,输入正确的验证码才允许继续访问网站
	blockAction = "captcha",

	-- 访问验证码页面超过一定次数加入到灰2名单
	captchaToGray2 = { state = true, maxReqs = 10 , amongTime = 120},

	-- 表示http-guard封锁ip的灰1名单时间
	gray1Time = 600,

    -- 表示http-guard封锁的ip的灰2名单时间
	gray2Time = 7200,

	-- JsJumpModules 验证通过后,ip在白名单的时间
	whiteTime = 7200,

	-- 用于生成token密码的key过期时间
	keyExpire = 600,

	-- 匹配url模式，可选值requestUri,uri
	-- 值requestUri时,url正则匹配的是浏览器最初请求的地址且没有被decode,带参数的链接
	-- 值为uri时, url正则匹配的是经过重写过的地址,不带参数,且已经decode.
	urlMatchMode = "uri",
	
	-- 验证码页面路径,一般不需要修改
	captchaPage = baseDir.."html/captcha.html",

	-- 输入验证码错误时显示的页面路径,一般不需要修改
	reCaptchaPage = baseDir.."html/reCatchaPage.html",

	-- 输入验证码错误时显示的页面路径,一般不需要修改
	gray2Page = baseDir.."html/gray2Page.html",

	-- 白名单ip文件,文件内容为正则表达式。
	whiteIpModules = { state = true, ipTables = ipWhitelist },

	-- 黑名单ip文件,文件内容为正则表达式。
	blackIpModules = { state = true, ipTables = ipBlacklist },

	-- 指定验证码图片目录,一般不需要修改
	captchaDir = baseDir.."captcha/",

	-- 是否开启debug日志
	debug = false,

	--日志目录,一般不需要修改.但需要设置logs所有者为nginx运行用户，如nginx运行用户为www，则命令为chown www logs
	logPath = baseDir.."logs/",
}

return Config
