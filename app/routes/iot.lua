local pairs = pairs
local ipairs = ipairs
local smatch = string.match
local slower = string.lower
local ssub = string.sub
local slen = string.len
local pbkdf2 = require "resty.nettle.pbkdf2"
local base64 = require "resty.nettle.base64"
local hmac = require "resty.nettle.hmac"
local gsub = string.gsub
local byte = string.byte
local format = string.format
local cjson = require("cjson")
local utils = require("app.libs.utils")
local pwd_secret = require("app.config.config").pwd_secret
local lor = require("lor.index")
local user_model = require("app.model.user")
local iot_router = lor:Router()
local config  = require("app.config.config")
local redis = require "resty.redis"
local ckobj = require "lor.resty.cookie"
local rand = math.random




G_OLDPASS = 'oldpass'
G_NEWPASS = 'newpass'
G_REGISTER = 'register'
G_PHONE = 'phone'
G_UUID = 'uuid'
G_KEY = 'key'
G_EMAIL = 'email'
G_PASSWORD = 'password'
G_IPADDR = 'ipaddr'
G_SIGN = 'sign'
G_CAPTCHA = 'captcha'
G_NAME = 'name'
G_UNAME = 'uname'
G_REMOTE_ADDR = 'REMOTE_ADDR'
G_SMSCODE = 'smscode'
G_CSRFTOKEN = 'csrftoken'
G_DEVID  = 'devid'
G_APPID = 'appid'
G_TOPICS = 'topics'
G_DKEY   = 'dkey'
G_MSG = 'msg'
G_OK = 'ok'
G_ERR = 'err'
G_DATA = 'data'
G_EXPIRE = 'expire'
G_SRVS = 'srvs'
G_VER = 'ver'
G_RESCODE = 'rescode'
G_SMS= 'sms'
G_SESSIONID = 'sessionid'
G_ACCOUNT = 'account'
G_SETCOOKIE = 'Set-Cookie'


local function hex(str,spacer)
    return (gsub(str,"(.)",function (c)
        return format("%02x%s",byte(c),spacer or "")
        end))
end

local alnum  = {
'0','1','2','3','4','5','6','7','8','9',
'a','b','c','d','e','f','g','h','i','j','k','l','m',
'n','o','p','q','r','s','t','u','v','w','x','y','z',
'A','B','C','D','E','F','G','H','I','J','K','L','M',
'N','O','P','Q','R','S','T','U','V','W','X','Y','Z'
}

local function get_code(str,spacer)
    return (gsub(str,"(.)",function(c)
        return alnum[tonumber(byte(c)) % #alnum]
        end))
end


local function get_new_cookie()
    local output = {}
    local l = #alnum
    local pos = rand(1,l - 10) + 10
    table.insert(output,alnum[pos])
    for i = 2, 32 do
        pos = rand(1,l)
        table.insert(output,alnum[pos])
    end

    output = table.concat(output)
    txt = output .. tostring(os.time()) .. config.session_secret
    local raw = hex(hmac.sha1.new(txt):digest())
    local ret = "sessionid=" .. raw .. "; Max-Age=" .. tostring(config.settings.SESSION_COOKIE_AGE)
    .. "; expire=" .. ngx.http_time(ngx.now() + 28800 + config.settings.SESSION_COOKIE_AGE) .. "; httponly; Path=/"

    return raw,ret
end

local function RedisDB()
    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeout(1000)
    local ok,err = red:connect("127.0.0.1",6379)
    if not ok then
        ngx.log(ngx.ERR,"failed to connect: ",err)
        return nil,err
    end
    ok,err = red:select(1)
    if not ok then
        ok , err = red:auth(config.redis.auth)
        if not ok then
            return nil,err
        end
        ok,err = red:select(1)
    end

    return red,err
end





local UnkownSignMethod = {err="UnkownSignMethod", msg="未知签名方法", ok=false}
local SignError = {err="SignError", msg="签名错误", ok=false}
local DataMiss = {err="DataMiss", msg="信息不完整", ok=false}
local UserNotExists = {err= "UserNotExists", msg="用户不存在", ok=false}
local UnAuth = {err= "UnAuth", msg="无权访问", ok=false}
local TargetNotExists = {err= "TargetNotExists", msg="目标不存在", ok=false}
local TargetIsSelf = {err= "TargetIsSelf", msg="目标不能是自已", ok=false}
local UnkownAction = {err="UnkownAction", msg="未识别的操作", ok=false}
local BindError = {err="BindError", msg="已经绑定", ok=false}
local BindPWDError = {err="BindError", msg="无权绑定", ok=false}
local UserError = {err="UserError", msg="用户名已存在", ok=false}
local EmailError = {err="EmailError", msg="邮箱已存在", ok=false}
local PhoneError = {err="PhoneError", msg="手机号已存在", ok=false}
local PwdError = {err="PwdError", msg="密码或者用户错误", ok=false}
local ArgError = {err="ArgError", msg="参数错误", ok=false}
local CaptchaError = {err="CaptchaError", msg="验证码错误", ok=false}
local IpAddrError = {err="IpAddrError", msg="IP错误", ok=false}
local InternalError = {err="InternalError", msg="服务器内部错误", ok=false}
local SmsOverError = {err="SmsOverError", msg="该手机号已经超过发送次数", ok=false}
local SmsIntervalError = {err="SmsIntervalError", msg="发送间隔太短", ok=false}
local OtherError = {err="OtherError", msg="发送间隔太短", ok=false}
local PhoneInactive = {err="PhoneInactive", msg="该手机号没有验证激活", ok=false}
local FormatError = {err="FormatError", msg="格式错误", ok=false}
local DevActError = {err="DevActError", msg="设备未出厂", ok=false}


local function list_todict(lst)
    local result = {}
    local nextkey
    if type(lst) ~= "table" then
        return nil
    end
    for k,v in ipairs(lst) do
        if k % 2 == 1 then
            nextkey = v
        else
            result[nextkey] = v
        end
    end
    return result
end

local function debug_table(t)
    if not t then
        ngx.say("tables is nil")
        return nil
    end
    ngx.say("debug  print " .. tostring(t) .. " len " .. #t)
    for k,v in pairs(t) do
        if type(v) == "string" then
            ngx.say(" key: ",k," value: ",v)
        else
            ngx.say(" key: ",k, " value: ",type(v))
        end
    end
end


local function check_cookie(req,res)

    if not ngx.var.http_cookie then
        res:set_header('Set-Cookie',get_new_cookie())
        return false
    end
    return true
end


-- 这里是为了兼django插入的加密认证方式, key = "<algorithm>$<iterations>$<salt>$<hash>"
local function check_password(oldpwd,newpwd)
    local algorithm,iterations,salt,hash = string.match(oldpwd,"(%w+_%w+)%$(%d+)%$(%w+)%$([A-Za-z0-9+/=]+)")
    if not algorithm or not iterations or not salt  or not hash then
        return false
    end
    local hmac
    if algorithm == "pbkdf2_sha256" then
        hmac = pbkdf2.hmac_sha256(newpwd,tonumber(iterations),salt,32)
        elseif algorithm == "pbkdf2_sha1" then
            hmac = pbkdf2.hmac_sha1(newpwd,tonumber(iterations),salt,20)
        end

        if hash == base64.encode(hmac) then
            return true
        end

        return false
end



local function response_login(uuid,key,tokenlist,sessionid)
    -- ngx.log(ngx.ERR,"uuid local value is " .. uuid)
    local ok,red,err,srvres
    srvres ,err = user_model:query_by_mqtt_srv()
    local servers = nil
    if  not err then
        servers = srvres.ipaddr  .. ":" .. srvres.port
    end


    retable = {}
    retable.ok= true
    retable.sign =  sessionid
    retable.expire = config.settings.SESSION_COOKIE_AGE
    retable.uuid = uuid
    if servers then
        retable.srvs= servers
    end


    red,err = RedisDB()
    if err then
        ngx.say(" redis server error ")
     end

 local sha256 = hmac.sha256.new(key)
 local dictable = {}
 dictable[G_PASSWORD] = hex(sha256:digest())
 dictable[G_UUID] = uuid
 dictable[G_IPADDR] = ngx.var.remote_addr
 dictable["res"] = cjson.encode(retable)
 dictable[G_ACCOUNT] = cjson.encode(tokenlist)
 ok,err = red:hmset(sessionid,dictable)
 if err then
    ngx.say("hmset failed")
end
ok,err = red:expire(sessionid,config.settings.SESSION_COOKIE_AGE)
if err then
    ngx.say("expire time failed")
end
ok,err = red:set_keepalive(10000,100)

return retable
end

iot_router:post("/dev/auth/:usertoken/:userpass/",function(req,res,next)

    -- 检查有没有登录记录
    local usertoken = req.params.usertoken
    local userpass =  req.params.userpass

    if ngx.var.http_cookie then
        local _,sessionid = string.match(ngx.var.http_cookie,"(%w+)=(%w+)")
        ngx.say(" get client cookie is ",sessionid)
        local red,err = RedisDB()
        if err then
            ngx.say(" redis server error ",err)
        end

     local auth_cache,err = red:hgetall(sessionid)
        if not err then
            local dict = list_todict(auth_cache)
            if dict[G_IPADDR] == ngx.var.remote_addr and
                dict[G_UUID] == usertoken then
                red:expire(config.settings.SESSION_COOKIE_AGE)
                local restable = cjson.decode(dict.res)
                restable.time = ngx.time()
                return res:json(restable)
            end
        end
    end

    if not usertoken or not userpass or usertoken == "" or userpass == "" then
        return res:json(DataMiss)
    end
    local result,err = user_model:query_by_iot_dev_login(usertoken)
    if err or not result then
        return res:status(403):json(PwdError)
    end
    local uuid ,key
    uuid = result.uuid
    key = result.key

    ngx.log(ngx.ERR," uuid " .. uuid .. " key " .. key)
    if uuid and key then
        if check_password(key,tostring(userpass)) then
            user_model:insert_dev_login(uuid,ngx.var.remote_addr)
            return res:json(response_login(uuid,key,nil))
        end
    end
    return res:status(403):json(PwdError)

    end)


iot_router:post("/app/auth/:usertoken/:userpass/",function(req,res,next)
    local usertoken = req.params.usertoken
    local userpass =  req.params.userpass

    if ngx.var.http_cookie then
        local _,sessionid = string.match(ngx.var.http_cookie,"(sessionid)=(%w+)")
        local red,err = RedisDB()
        if err then
            ngx.say(" redis server error ",err)
        end

        local auth_cache,err = red:hgetall(sessionid)
        debug_table(auth_cache)
        if not err and auth_cache then
            local dict = list_todict(auth_cache)
            if dict then
                -- ngx.say(" auth from cache ",string.find(dict[G_ACCOUNT],usertoken))
                if dict[G_IPADDR] == ngx.var.remote_addr and
                    string.find(dict[G_ACCOUNT],usertoken) then
                    red:expire(sessionid,config.settings.SESSION_COOKIE_AGE)
                    local restable = cjson.decode(dict.res)
                    restable.time = ngx.time()
                    return res:json(restable)
                end
            end
        end
    end

    local sessionid,cookie = get_new_cookie()
    res:set_header(G_SETCOOKIE,cookie)
    -- ngx.log(ngx.ERR,"uuid  ",result.uuid," key ",result.key, " active ",result.phone_active)
    if not usertoken or not userpass or usertoken == "" or userpass == "" then
        return res:status(403):json(DataMiss)
    end
    local result,err = user_model:query_by_iot_app_login(usertoken)
    if err or not result then
        return res:status(403):json(PwdError)
    end

    local uuid,key,phone_active,phone,email
    uuid = result.uuid
    key = result.key
    phone_active  = result.phone_active
    phone = result.phone
    email = result.email

    if not phone_active then
        return res:json(PhoneInactive)
    end

    if result and not err then
        if check_password(key,tostring(userpass)) then
            -- 登录成功
            uuid = gsub(uuid,'-',"")
            local tokenlist = {uuid,usertoken,phone,email}
            retable = response_login(uuid,key,tokenlist,sessionid)
            retable.time = ngx.time()
            user_model:insert_app_login(retable.uuid,ngx.var.remote_addr)
            return res:json(retable)
        else
            return res:status(403):json(PwdError)
        end
    end
    return res:status(403):json(UserNotExists)
end)



local function AppBindDev(req,res,token)
    debug_table(req)
    local post_args = ngx.req.get_post_args()
    debug_table(post_args)
    local dev = req.parms.target
    
    local result,err =  user_model:query_dev_test(dev)
    if result then
        res:json(BindError)
    end
    result,err = user_model:query_makerdb(dev)
    if not result then
        res:json(TargetNotExists)
    end

    if result.status < 3 then
        res:json(DevActError)
    end
    user_model:insert_new_devices(result,ngx.var.remote_addr)
    if not check_password(result.key,post_args.dkey) then
        return res:json(PwdError)
    end 
    return res:json({ok = G_OK})


end

local function AppCheckBindDev()
end

local function  AppDropDev()
end

local optFunc = {}
optFunc["bind"] = AppBindDev()
optFunc["checkbind"] = AppBindDev
optFunc["unbind"] = AppBindDev
optFunc["reqshare"] = AppBindDev
optFunc["sharedev"] = AppBindDev

-- local optFunc = {bind = AppBindDev,
-- checkbind = AppCheckBindDev,
-- unbind = AppDropDev,
-- reqshare = AcceptBindLink,
-- sharedev = AppShareDev }

iot_router:post("/app/opt/:target/:action/",function(req,res,next)
    if not ngx.var.http_cookie then
        return res:status(403):json(UnAuth)
    end

    local _,sessionid = string.match(ngx.var.http_cookie,"(sessionid)=(%w+)")
    local red,err = RedisDB()
    if err then
        ngx.say(" redis server error ",err)
    end

    local auth_cache,err = red:hgetall(sessionid)
    if err then
        ngx.say(" error ",err," sessionid ",sessionid)
        return res:status(403):json(UnAuth)
    end

    local dict = list_todict(auth_cache)
    if dict[G_IPADDR] ~= ngx.var.remote_addr then
        return res:status(403):json(UnAuth)
    end

    local token = dict.uuid

    _,err = red:expire(sessionid,config.settings.SESSION_COOKIE_AGE)

    if optFunc[req.params.action] == nil then
        return res:status(403):json(UnkownAction)
    end
    debug_table(user_model)
    debug_table(optFunc)
    ngx.say("this type is ",type(optFunc[action]))
    return optFunc[action](req,res,token)
    end)

iot_router:post("/app/getinfo/",function(req,res,next)
    if not ngx.var.http_cookie then
        return res:status(403):json(UnAuth)
    end

    local _,sessionid = string.match(ngx.var.http_cookie,"(sessionid)=(%w+)")
    local red,err = RedisDB()
    if err then
        ngx.say(" redis server error ",err)
    end

    local auth_cache,err = red:hgetall(sessionid)
    if err then
        ngx.say(" error ",err)
        return res:status(403):json(UnAuth)
    end
    local dict = list_todict(auth_cache)
    if dict[G_IPADDR] ~= ngx.var.remote_addr then
        debug_table(dict)
        return res:status(403):json(UnAuth)
    end
    return res:json({ok=true})

end)


return iot_router

