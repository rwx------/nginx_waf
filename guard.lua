local Guard = {}

--debug日志
function Guard:debug(data,ip,reqUri)
	if _Conf.debug then
		local date = os.date("%Y-%m-%d")
        local filename = _Conf.logPath.."/debug-"..date..".log"
        local method =  ngx.var.request_method
		--local filename = "/data/www/waf/logs/test.log"
		local file = io.open(filename,"a+")
		file:write(os.date('%Y-%m-%d %H:%M:%S').." [DEBUG] "..data.." IP "..ip.." "..method.." "..reqUri.."\n")
		file:close()
	end
end

--攻击日志
function Guard:log(data)
	local date = os.date("%Y-%m-%d")
	local filename = _Conf.logPath.."/attack-"..date..".log"
	local file = io.open(filename,"a+")
	file:write(os.date('%Y-%m-%d %H:%M:%S').." [WARNING] "..data.."\n")
	file:close()	
end

-- ip转换为十进制
function Guard:ipToDecimal(ckip)
    local n = 4
    local num = 0
    local pos = 0
    for st, sp in function() return string.find(ckip, '.', pos, true) end do
        n = n - 1
        num = num + string.sub(ckip, pos, st-1) * (256 ^ n)
        pos = sp + 1
        if n == 1 then num = num + string.sub(ckip, pos, string.len(ckip)) end
    end
    return num
end

--获取真实ip
function Guard:getRealIp()
    if ngx.var.http_cdn_src_ip then
        clientIp = ngx.var.http_cdn_src_ip
	    self:debug("[getRealIp] get ip from http_cdn_src_ip: "..clientIp, ngx.var.http_cdn_src_ip, "")
    elseif ngx.var.http_x_forwarded_for then
        clientIp = ngx.var.http_x_forwarded_for
        local s = string.find(clientIp, ',', 0, true)
        if s then
            clientIp = string.sub(clientIp, 0, s - 1)
        end
	    self:debug("[getRealIp] get ip from http_x_forwarded_for: "..clientIp, ngx.var.http_x_forwarded_for, "")
    else
        clientIp = ngx.var.remote_addr
    end
    local regex = [[^([0-9]{1,3}\.){3}[0-9]{1,3}$]]
    local m =  ngx.re.match(clientIp, regex, "o")
    if not m then
        clientIp = "0.0.0.0"
	    self:debug("[getRealIp] error: can't get the clientIp.","","")
    end
    return clientIp
end

--白名单模块
function Guard:ipInWhiteList(ip)
    local ua = ngx.var.http_user_agent
    local whiteKey = ngx.md5(ip..ua).."whitekey" --定义white key
    local white = _Conf.dict:get(whiteKey)
    if white then
        self:debug("[ipInWhiteList] match whiteKey: "..white..":"..whiteKey ,ip,"")
        return true
    end

    --匹配白名单列表
    for _, tables in pairs(_Conf.whiteIpList) do 
        if type(tables) == "table" then
            for _, i in pairs(tables) do
                local s, e = string.find(i, '-', 0, true)
                if s then
                    numIp = tonumber(self:ipToDecimal(ip))
                    sIp = tonumber(self:ipToDecimal(string.sub(i, 0, s - 1)))
                    eIp = tonumber(self:ipToDecimal(string.sub(i, e + 1, string.len(i))))
                    if numIp >= sIp and numIp <= eIp then
                        self:debug("[ipInWhiteList] match ipWhiteList range: " .. i ,ip,"")
                        return true
                    end
                elseif ip == i then
                        self:debug("[ipInWhiteList] match ipWhiteList: " .. i ,ip,"")
                    return true
                end
            end
        end
    end
    return false
end

--黑名单模块
function Guard:blackListModules(ip,reqUri)
    --匹配黑名单列表
    for _, tables in pairs(_Conf.blackIpList) do 
        if type(tables) == "table" then
            for _, i in pairs(tables) do
                local s, e = string.find(i, '-', 0, true)
                if s then
                    numIp = tonumber(self:ipToDecimal(ip))
                    sIp = tonumber(self:ipToDecimal(string.sub(i, 0, s - 1)))
                    eIp = tonumber(self:ipToDecimal(string.sub(i, e + 1, string.len(i))))
                    if numIp >= sIp and numIp <= eIp then
                        self:debug("[blackListModules] return forbiddenAction",ip,reqUri)
                        self:forbiddenAction()
                    end
                elseif ip == i then
                    self:debug("[blackListModules] return forbiddenAction",ip,reqUri)
                    self:forbiddenAction()
                end
            end
        end
    end
end

-- 灰1名单模块
function Guard:gray1ListModules(ip,reqUri)
    local ua = ngx.var.http_user_agent
	local gray1Key = ngx.md5(ip..ua).."gray1"

    --匹配灰名单字典
    if _Conf.dict:get(gray1Key) then
        self:debug("[gray1ListModules] ip "..ip.." in gray1list",ip,reqUri)
        self:gray1Action(ip,reqUri) --存在则执行相应动作
    end

end

-- 灰2名单模块
function Guard:gray2ListModules(ip,reqUri)
    local ua = ngx.var.http_user_agent
	local gray2Key = ngx.md5(ip..ua).."gray2"

    --匹配灰名单字典
    if _Conf.dict:get(gray2Key) then
        self:debug("[gray2ListModules] ip "..ip.." in gray2list",ip,reqUri)
        self:gray2Action() --存在则执行相应动作
    end

end

--限制请求速率模块
function Guard:limitReqModules(ip,reqUri,address)
    for _, u in pairs(_Conf.limitUrlProtect) do
        if ngx.re.match(address,u,"io") then	
            self:debug("[limitReqModules] address "..address.." match reg "..u,ip,reqUri)	
            local ua = ngx.var.http_user_agent
            local gray1Key = ngx.md5(ip..ua).."gray1"
            local limitReqKey = ngx.md5(ip..ua).."limitreqkey" --定义limitreq key
            local reqTimes = _Conf.dict:get(limitReqKey) --获取此ip请求的次数

            --增加一次请求记录
            if reqTimes then
                _Conf.dict:incr(limitReqKey, 1)
            else
                _Conf.dict:set(limitReqKey, 1, _Conf.limitReqModules.amongTime)
                reqTimes = 0
            end

            local newReqTimes  = reqTimes + 1
            self:debug("[limitReqModules] newReqTimes "..newReqTimes,ip,reqUri)

            --判断请求数是否大于阀值,大于则添加灰1名单
            --判断是否请求数大于阀值
            if newReqTimes > _Conf.limitReqModules.maxReqs then 
                self:debug("[limitReqModules] ip "..ip.. " request exceed ".._Conf.limitReqModules.maxReqs,ip,reqUri)
                --添加此ip到灰1名单
                _Conf.dict:set(gray1Key,0,_Conf.gray1Time) 
                self:log("[limitReqModules] IP "..ip.." visit "..newReqTimes.." times,block it.")
            end
        end
    end
end

--获取验证码
function Guard:getCaptcha()
	math.randomseed(ngx.now()) --随机种子
	local random = math.random(1,10000) --生成1-10000之前的随机数
	self:debug("[getCaptcha] get random num "..random,"","")
	local captchaValue = _Conf.dict_captcha:get(random) --取得字典中的验证码
        self:debug("[getCaptcha] get captchaValue "..(captchaValue or "nil"),"","")
	local captchaImg = _Conf.dict_captcha:get(captchaValue) --取得验证码对应的图片
	--返回图片
	ngx.header.content_type = "image/jpeg"
	ngx.header['Set-Cookie'] = table.concat({"captchaNum=",random,"; path=/"})

    -- 不做缓存，CDN优化
    ngx.header.Cache_control = "no-cache,no-store,private"
    ngx.header.pragma = "no-cache"

	ngx.print(captchaImg)
	ngx.exit(200)	
end

 --验证验证码
function Guard:verifyCaptcha(ip)
	ngx.req.read_body()
	local captchaNum = ngx.var["cookie_captchaNum"] --获取cookie captchaNum值
	local preurl = ngx.var["cookie_preurl"] --获取上次访问url
	self:debug("[verifyCaptcha] get cookie captchaNum "..captchaNum,ip,"")
	local args = ngx.req.get_post_args() --获取post参数
	local postValue = args["response"] --获取post value参数
	postValue = string.lower(postValue)
	self:debug("[verifyCaptcha] get post arg response "..postValue,ip,"")
	local captchaValue = _Conf.dict_captcha:get(captchaNum) --从字典获取post value对应的验证码值
	if captchaValue == postValue then --比较验证码是否相等
		self:debug("[verifyCaptcha] captcha is valid.delete from blacklist",ip,"")
        local ua = ngx.var.http_user_agent
        local gray1Key = ngx.md5(ip..ua).."gray1"
        local limitReqKey = ngx.md5(ip..ua).."limitreqkey" --定义limitreq key
        local whiteKey = ngx.md5(ip..ua).."whitekey" --定义limitreq key
		_Conf.dict:delete(gray1Key) --从灰1名单删除
		_Conf.dict:delete(limitReqKey) --访问记录删除
		_Conf.dict:set(whiteKey,1,_Conf.whiteTime) --加入白名单
		local expire = ngx.time() + _Conf.keyExpire
		local captchaKey = ngx.md5(table.concat({ip,_Conf.captchaKey,expire}))
		local captchaKey = string.sub(captchaKey,"1","10")
		self:debug("[verifyCaptcha] expire "..expire,ip,"")
		self:debug("[verifyCaptcha] captchaKey "..captchaKey,ip,"")	
		ngx.header['Set-Cookie'] = {"captchaKey="..captchaKey.."; path=/", "captchaExpire="..expire.."; path=/"}
		return ngx.redirect(preurl) --返回上次访问url
	else
        local ua = ngx.var.http_user_agent
		local captchaReqKey = ngx.md5(ip..ua).."captchareqkey" --定义captcha req key
		local reqTimes = _Conf.dict:get(captchaReqKey) --获取此ip验证码请求的次数

		--增加一次请求记录
		if reqTimes then
			_Conf.dict:incr(captchaReqKey, 1)
		else
			_Conf.dict:set(captchaReqKey, 1, _Conf.captchaGray2.amongTime)
			reqTimes = 0
		end

		local newReqTimes  = reqTimes + 1
		self:debug("[verifCaptcha] newReqTimes "..newReqTimes,ip,"")

		-- 验证码请求数是否大于阀值, 否则直接返回灰2页面
		if newReqTimes > _Conf.captchaGray2.maxReqs then --判断是否请求数大于阀值
		    self:debug("[verifyCaptcha] ip+ua exceeds gray2 maxReqs "..newReqTimes,ip,"")
            local gray2Key = ngx.md5(ip..ua).."gray2"
            _Conf.dict:set(gray2Key, 1, _Conf.gray2Time)
            self:gray2Action()    
        else
            --重新发送验证码页面
            self:debug("[verifyCaptcha] captcha invalid",ip,"")
            ngx.header.content_type = "text/html"

            -- 不做缓存，CDN优化
            ngx.header.Cache_control = "no-cache,no-store,private"
            ngx.header.pragma = "no-cache"

            ngx.print(_Conf.reCaptchaPage)
            ngx.exit(200)
        end
	end 
end

--灰2动作，返回一个封禁时间的页面
function Guard:gray2Action()
		ngx.header.content_type = "text/html"

        -- 不做缓存，CDN优化
        ngx.header.Cache_control = "no-cache,no-store,private"
        ngx.header.pragma = "no-cache"

        ngx.print(_Conf.gray2Page)
		ngx.exit(403)
end

--拒绝访问动作
function Guard:forbiddenAction()
		ngx.header.content_type = "text/html"

        -- 不做缓存，CDN优化
        ngx.header.Cache_control = "no-cache,no-store,private"
        ngx.header.pragma = "no-cache"

		ngx.exit(403)
end

--展示验证码页面动作
function Guard:captchaAction(ip,reqUri)
	-- 访问验证码超过一定次数,加入灰2名单
	if _Conf.captchaGray2ModulesIsOn then
        local ua = ngx.var.http_user_agent
		local captchaReqKey = ngx.md5(ip..ua).."captchareqkey" --定义captcha req key
		local reqTimes = _Conf.dict:get(captchaReqKey) --获取此ip验证码请求的次数
		--增加一次请求记录
		if reqTimes then
			_Conf.dict:incr(captchaReqKey, 1)
		else
			_Conf.dict:set(captchaReqKey, 1, _Conf.captchaGray2.amongTime)
			reqTimes = 0
		end

		local newReqTimes  = reqTimes + 1
		self:debug("[captchaAction] newReqTimes "..newReqTimes,ip,reqUri)

		--判断请求数是否大于阀值, 否则加入灰2度模块
		if newReqTimes > _Conf.captchaGray2.maxReqs then --判断是否请求数大于阀值
            local gray2Key = ngx.md5(ip..ua).."gray2"
			self:debug("[captchaAction] ip "..ip.. " request exceed ".._Conf.captchaGray2.maxReqs,ip,reqUri)
			self:log("[captchaAction] IP "..ip.." visit "..newReqTimes.." times,iptables block it.")
            _Conf.dict:set(gray2Key, 1, _Conf.gray2Time)
		end
	end

	ngx.header.content_type = "text/html"
	ngx.header['Set-Cookie'] = table.concat({"preurl=",reqUri,"; path=/"})

    -- 不做缓存，CDN优化2
    ngx.header.Cache_control = "no-cache,no-store,private"
    ngx.header.pragma = "no-cache"

	ngx.print(_Conf.captchaPage)
	ngx.exit(200)
end

--执行相应动作
function Guard:gray1Action(ip,reqUri)
    local cookie_key = ngx.var["cookie_captchaKey"] --获取cookie captcha密钥
    local cookie_expire = ngx.var["cookie_captchaExpire"] --获取cookie captcha过期时间
    if cookie_expire and cookie_key then
        local now = ngx.time()
        local key_make = ngx.md5(table.concat({ip,_Conf.captchaKey,cookie_expire}))
        local key_make = string.sub(key_make,"1","10")
        self:debug("[gray1Action] cookie_expire "..cookie_expire,ip,reqUri)
        self:debug("[gray1Action] cookie_key "..cookie_key,ip,reqUri)
        self:debug("[gray1Action] now "..now,ip,reqUri)
        self:debug("[gray1Action] key_make "..key_make,ip,reqUri)
        if tonumber(cookie_expire) > now and cookie_key == key_make then
            self:debug("[gray1Action] cookie key is valid.",ip,reqUri)
            return
        else
            self:debug("[gray1Action] cookie key is invalid",ip,reqUri)
            self:captchaAction(ip,reqUri)
        end	
    else	
        self:debug("[gray1Action] return captchaAction",ip,reqUri)
        self:captchaAction(ip,reqUri)
    end	
end

return Guard
