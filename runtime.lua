local Guard = require "guard"
local ip = Guard:getRealIp()
local reqUri = ngx.var.request_uri
local uri = ngx.var.uri
local address = ''
local limitModule = ngx.var.limit_module
local redirectModule = ngx.var.redirect_module
local jsModule = ngx.var.js_module
local cookieModule = ngx.var.cookie_module

--判断是某种url匹配模式
if _Conf.urlMatchMode == 'uri' then
	address = uri
else
	address = reqUri
end	

--获取验证码
if ngx.re.match(uri,"/get-captcha.jpg$","io") then
	Guard:getCaptcha()

--验证验证码
elseif ngx.re.match(uri,"/verify-captcha.jpg$","io") then
	Guard:verifyCaptcha(ip)

--过滤请求
else
	--白名单模块
	if not Guard:ipInWhiteList(ip) and not Guard:uaInWhiteList(ip) then

		--黑名单模块
		Guard:blackListModules(ip,reqUri)

        -- 灰2度模块（即超过验证码页面次数的，封2h）
        Guard:gray2ListModules(ip, reqUri) 

        -- 灰1度模块（即超过频率的，跳转到验证码页面）
        Guard:gray1ListModules(ip,reqUri)

		--限制请求速率模块
		if _Conf.limitReqModulesIsOn then --limitReq模块是否开启
            Guard:limitReqModules(ip,reqUri,address)
		end

	end	
end
