--require 'ip_list'
local Config = require("config")

--开关转换为true或false函数
local function optionIsOn(options)
	local options = string.lower(options)
	if options == "on" then
		return true
	else
		return false
	end	
end

--生成密码
local function makePassword()
	local string="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	math.randomseed(os.time()) --随机种子
	local r1 = math.random(1,62) --生成1-62之间的随机数
	local r2 = math.random(1,62) --生成1-62之间的随机数
	local r3 = math.random(1,62) --生成1-62之间的随机数
	local r4 = math.random(1,62) --生成1-62之间的随机数
	local r5 = math.random(1,62) --生成1-62之间的随机数
	local r6 = math.random(1,62) --生成1-62之间的随机数
	local r7 = math.random(1,62) --生成1-62之间的随机数
	local r8 = math.random(1,62) --生成1-62之间的随机数

	local s1 = string.sub(string,r1,r1)
	local s2 = string.sub(string,r2,r2)
	local s3 = string.sub(string,r3,r3)
	local s4 = string.sub(string,r4,r4)
	local s5 = string.sub(string,r5,r5)
	local s6 = string.sub(string,r6,r6)
	local s7 = string.sub(string,r7,r7)
	local s8 = string.sub(string,r8,r8)

	return s1..s2..s3..s4..s5..s6..s7..s8
end

--解析文件到正则字符串函数
local function parseRuleFile(filePath)
	local list = ''
	local rfile = assert(io.open(filePath,'r'))
	for line in rfile:lines() do
		if not (string.match(line,"^ *$")) then
			list = list.."|"..line
		end
	end
	list = string.gsub(list,"^%|",'')
	rfile:close()
	return list
end

--解析动作
local function actionIsOn1(action)
	if action == "captcha" then
		return true	
	else
		return false
	end	
end

local function actionIsOn2(action)
	if action == "forbidden" then
		return true
	else
		return false
	end	
end

local function actionIsOn3(action)
	if action == "iptables" then
		return true
	else
		return false
	end	
end

--解析uri匹配模式
local function urlMode1(mode)
	if mode == "uri" then
		return true
	else
		return false
	end
end

local function urlMode2(mode)
	if mode == "requestUri" then
		return true
	else
		return false
	end	
end


--读取文件到内存
local function readFile2Mem(file)
	local fp = io.open(file,"r")
	if fp then
		return fp:read("*a")
	end
end

--读取验证码到字典
local function readCaptcha2Dict(dir,dict) 
	local i = 0
	for path in io.popen('ls -a '..dir..'*.png'):lines() do
		if i < 10000 then
			i = i + 1
			local fp = io.open(path,"rb")
			local img = fp:read("*a")
			local captcha = string.gsub(path,".*/(.*)%.png","%1")
			captcha = string.lower(captcha)
			dict:set(i,captcha)
			dict:set(captcha,img)
		else
			break
		end	
	end	
end

_Conf = {
	
	--引入原始设置
	limitReqModules = Config.limitReqModules,
	JsJumpModules = Config.JsJumpModules,
	whiteIpModules = Config.whiteIpModules,
    captchaGray2 = Config.captchaToGray2,
	debug = Config.debug,
	logPath = Config.logPath,
	gray1Time = Config.gray1Time,
	gray2Time = Config.gray2Time,
	whiteTime = Config.whiteTime,
	keyExpire = Config.keyExpire,
	captchaKey = Config.captchaKey,

	--解析开关设置
    captchaGray2ModulesIsOn = Config.captchaToGray2.state,
	limitReqModulesIsOn = Config.limitReqModules.state,
	JsJumpModulesIsOn = Config.JsJumpModules.state,

	--解析文件到正则
	JsJumpUrlProtect = parseRuleFile(Config.JsJumpModules.urlProtect),
	limitUrlProtect = Config.limitReqModules.urlProtect,
	whiteIpList = Config.whiteIpModules.ipTables,
	blackIpList = Config.blackIpModules.ipTables,

	--读取文件到内存
	captchaPage = readFile2Mem(Config.captchaPage),
	reCaptchaPage = readFile2Mem(Config.reCaptchaPage),
	gray2Page = readFile2Mem(Config.gray2Page),

	--新建字典(用于记录ip访问次数及黑名单)
	dict = ngx.shared.guard_dict,

	--新建字典(只用于记录验证码,防止丢失)
	dict_captcha = ngx.shared.dict_captcha,

	--验证码图片路径
	captchaDir = Config.captchaDir,

	captchaAction = actionIsOn1(Config.blockAction),
	forbiddenAction = actionIsOn2(Config.blockAction),

	--解析url匹配模式
	uriMode = urlMode1(Config.urlMatchMode),
	requestUriMode = urlMode2(Config.urlMatchMode),

	normalCount = 0,
	exceedCount = 0,
}

--读取验证码到字典
if Config.blockAction == "captcha" then
	readCaptcha2Dict(_Conf.captchaDir,_Conf.dict_captcha)
end	

--判断JsJumpModules是否开启
if _Conf.JsJumpModulesIsOn then
	_Conf.dict_captcha:set("jsOn",1)
else
	_Conf.dict_captcha:set("jsOn",0)
end

--判断是否key是动态生成
if Config.keyDefine == "dynamic" then
	_Conf.JsJumpModules.keySecret = makePassword()
	_Conf.captchaKey = makePassword()
end	
