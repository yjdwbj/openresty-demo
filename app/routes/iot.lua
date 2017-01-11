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
        ok , err = red:auth("f4e4821080ca489d3361a520fc2123495755559b45fb24323c5b02e79163e425")
        if not ok then
            return nil,err
        end
        ok,err = red:select(1)
    end

    return red,err
end


local function list_todict(lst)
    local result = {}
    local nextkey
    for k,v in ipairs(lst) do
        if k % 2 == 1 then
            nextkey = v
        else
            result[nextkey] = v
        end
    end
    return result
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



local function debug_table(t)
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

local function redis_cmd(cmd,args)
    local red = redis:new()
    local ok,err = red:connect(config.redis.host,config.redis.port)
    red:select(1)
    if not ok then
        ok , err = red:auth(config.redis.auth)
        -- return ok,err
    end
    if not err then
        red:init_pipeline()
        red:hset(signid,"password",hex(sha256:digest()))
        red:hset(signid,"uuid",uuid)
        red:expire(signid,config.settings.SESSION_COOKIE_AGE)
        ok,err = red:commit_pipeline()
        if err then
            ngx.log(ngx.ERR,"redis commit  pipeline error",err)
        end
    end
    local ok,err = red:set_keepalive(10000,100)
    if not ok then
        ngx.log(ngx.ERR,"set keepalive error")
    end
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
        if #srvres == 2 then
            servers = srvres[1] .. ":" .. srvres[2]
        else
            servers = srvres.ipaddr  .. ":" .. srvres.port
        end
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
 -- ok,err = red:hmset(sessionid,{
 --    G_PASSWORD = hex(sha256:digest()),
 --    G_UUID = uuid, G_IPADDR = ngx.var.remote_addr,
 --    res = cjson.encode(retable),
 --    G_ACCOUNT=cjson.encode(tokenlist)
 --    })
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

iot_router:get("/dev/auth/:usertoken/:userpass/",function(req,res,next)

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
                ngx.say(" get auth from redis ")
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
    if #result == 2 then
        uuid = result[1]
        key = result[2]
    else
        uuid = result.uuid
        key = result.key
    end

    ngx.log(ngx.ERR," uuid " .. uuid .. " key " .. key)
    if uuid and key then
        if check_password(key,tostring(userpass)) then
            user_model:insert_dev_login(uuid)
            return res:json(response_login(uuid,key,nil))
        end
    end
    return res:status(403):json(PwdError)

    end)


iot_router:get("/app/auth/:usertoken/:userpass/",function(req,res,next)
    local usertoken = req.params.usertoken
    local userpass =  req.params.userpass

    if ngx.var.http_cookie then
        local _,sessionid = string.match(ngx.var.http_cookie,"(%w+)=(%w+)")
        local red,err = RedisDB()
        if err then
            ngx.say(" redis server error ",err)
        end

        local auth_cache,err = red:hgetall(sessionid)
        if not err then
            local dict = list_todict(auth_cache)
            -- ngx.say(" auth from cache ",string.find(dict[G_ACCOUNT],usertoken))
            if dict[G_IPADDR] == ngx.var.remote_addr and
                string.find(dict[G_ACCOUNT],usertoken) then
                ngx.say("auth from cache ")
                red:expire(sessionid,config.settings.SESSION_COOKIE_AGE)
                local restable = cjson.decode(dict.res)
                restable.time = ngx.time()
                return res:json(restable)
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

    if #result == 5 then
        uuid = result[1]
        key = result[2]
        phone_active = result[3]
        phone = result[4]
        email = result[5]
    else
        uuid = result.uuid
        key = result.key
        phone_active  = result.phone_active
        phone = result.phone
        email = result.email
    end

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
            user_model:insert_app_login(retable.uuid)
            return res:json(retable)
        else
            return res:status(403):json(PwdError)
        end
    end
    return res:status(403):json(UserNotExists)
end)



local function AppBindDev(request,token,target)
    local post_args = ngx.req.get_post_args()
    ngx.say(" post args is " .. type(post_args) .. " len " .. #post_args)
    for k,v in pairs(post_args) do
        ngx.say( " kkk is "  .. k .. " val " .. type(v))
    end

end

local function AppCheckBindDev()
end

local function  AppDropDev()
end

local optFunc = {bind = AppBindDev,
checkbind = AppCheckBindDev,
unbind = AppDropDev,
reqshare = AcceptBindLink,
sharedev = AppShareDev }

iot_router:post("/app/opt/:target/:action/",function(req,res,next)
    if not ngx.var.http_cookie then
        ngx.say(" not cookie ")
        return res:status(403):json(UnAuth)
    end

    local _,sessionid = string.match(ngx.var.http_cookie,"(sessionid)=(%w+)")
    local red,err = RedisDB()
    if err then
        ngx.say(" redis server error ",err)
    end

    local auth_cache,err = red:hgetall(sessionid)
    if err then
        -- ngx.say(" error ",err)
        return res:status(403):json(UnAuth)
    end

    local dict = list_todict(auth_cache)
    if dict[G_IPADDR] ~= ngx.var.remote_addr then
        return res:status(403):json(UnAuth)
    end

    local target = req.params.target
    local action = req.params.action

    _,err = red:expire(sessionid,config.settings.SESSION_COOKIE_AGE)

    if optFunc[action] == nil then
        ngx.say("action is nil ")
        return res:status(403):json(UnkownAction)
    end
    return optFunc[action](req,token,target)
    end)

iot_router:get("/app/getinfo/",function(req,res,next)
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

