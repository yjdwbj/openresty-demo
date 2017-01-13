local RDB = require("app.libs.rdb")
local WDB = require("app.libs.wdb")
local rdb = RDB:new()
local wdb = WDB:new()

local user_model = {}


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

function user_model:new(username, password, avatar)
    return db:query("insert into user(username, password, avatar) values(?,?,?)",
            {username, password, avatar})
end

function user_model:query_ids(usernames)
   local res, err =  rdb:query("select id from user where username in(" .. usernames .. ")")
   return res, err
end

function user_model:query(username, password)
   local res, err =  rdb:query("select * from user where username=? and password=?", {username, password})
   return res, err
end

function user_model:query_by_id(id)
    local result, err =  rdb:query("select * from user where id=?", {tonumber(id)})
    if not result or err or type(result) ~= "table" or #result ~=1 then
        return nil, err
    else
        return result[1], err
    end
end



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

setmetatable(user_model,{list_todict,list_todict()})

local function checkuuid(uuid)
    local x = "%x"
    local t = {x:rep(8),x:rep(4),x:rep(4),x:rep(4),x:rep(12)}
    local t2 = x:rep(32)
    local pattern = table.concat(t,'%-')
    if string.match(uuid,pattern) or string.match(uuid,t2) then
        return true
    else
        return false
    end
end




function user_model:query_by_iot_app_login(uuid)

    local res,err
    if checkuuid(uuid) then
        res,err = rdb:query("select uuid,key,phone_active,phone,email from user_manager_appuser where uname=? or uuid=?",{uuid,uuid})
    else
        res,err = rdb:query("select uuid,key,phone_active,phone,email from user_manager_appuser where uname=? or email=? or  phone=?", {uuid,uuid,uuid})
    end
    if not res or err or type(res) ~= "table" then
        return nil,err or "error"
    end
    debug_table(res[1])
    return res[1],err
end

function user_model:query_by_iot_dev_login(uuid)
    local res,err
    if checkuuid(uuid) then
        res,err = rdb:query("select uuid,key from user_manager_devices where  uuid=?",{uuid})
    else
        return nil
    end

    if not res or type(res) ~= "table" then
        return nil,err
    end

    return list_todict(res[1]),err
end

function user_model:query_by_mqtt_srv()
    local res,err = rdb:query("select ipaddr,port from user_manager_srvlist order by concount ASC limit 1")
    if not res or err or #res ~=1 then
        return nil,err or "error"
    end
    return res[1],err
end

local function get_or_create(ipaddr)
    local res,err = rdb:query("select id from iplist where ipaddr=?;",{ipaddr})
    if not res or type(res) ~= "table" then
        res,err = wdb:query("insert into iplist (ipaddr) values(?);",{ipaddr})
        res,err = rdb:query("select id from iplist where ipaddr=?;",{ipaddr})
        debug_table(res)
    end
    return res[1],err
end

function user_model:insert_app_login(uuid,addr)
    -- local timestamp = string.format("%d",os.time())
    return  wdb:query("insert into user_manager_appuserloginhistory(inout,optime,ipaddr_id,user_id) values('true','now',1,?)",
                      {get_or_create(addr),uuid})

end

function user_model:insert_dev_login(uuid,addr)
    -- local timestamp = string.format("%d",os.time())
    return  wdb:query("insert into user_manager_devicesloginhistory(inout,optime,ipaddr_id,user_id) values('true','now',?,?)",
                      {get_or_create(addr),uuid})
end

function user_model:query_bindlist_test(uuid)
   	local res, err =  rdb:query("select 1 from bindlist where uuid=?", {uuid})
   	if not res or err or type(res) ~= "table" or #res ~=1 then
		return nil, err or "error"
	end
    debug_table(res[1])
	return res[1], err
end

function user_model:query_dev_test(uuid)
   	local res, err =  rdb:query("select 1 from user_manager_devices where uuid=?", {uuid})
   	if not res or err or type(res) ~= "table" or #res ~=1 then
		return nil, err or "error"
	end
    debug_table(res[1])
	return res[1], err
end


function user_model:insert_new_devices(dev)
    local res,err = wdb:query("insert into user_manager_devices \
        (mac,uuid,appkey,key,name,regip,regtime)  values(?,?,?,?,?,'now');",
        {dev.iot_mac,dev.uuid,dev.appkey,dev.key,dev.name,get_or_create(ipaddr)})
    return res,err
end

function user_model:query_makerdb(uuid)
   	local res, err =  rdb:query("select * from user_manager_devices where uuid=?", {uuid})
   	if not res or err or type(res) ~= "table" or #res ~=1 then
		return nil, err or "error"
	end
    debug_table(res[1])
	return res[1], err

end

    


-- return user, err
function user_model:query_by_username(username)
   	local res, err =  rdb:query("select * from user where username=? limit 1", {username})
   	if not res or err or type(res) ~= "table" or #res ~=1 then
		return nil, err or "error"
	end
	return res[1], err
end

function user_model:update_avatar(userid, avatar)
    wdb:query("update user set avatar=? where id=?", {avatar, userid})
end

function user_model:update_pwd(userid, pwd)
    local res, err = wdb:query("update user set password=? where id=?", {pwd, userid})
    if not res or err then
        return false
    else
        return true
    end

end

function user_model:update(userid, email, email_public, city, company, github, website, sign)
    local res, err = wdb:query("update user set email=?, email_public=?, city=?, company=?, github=?, website=?, sign=? where id=?",
        { email, email_public, city, company, github, website, sign, userid})

    if not res or err then
        return false
    else
        return true
    end
end

function user_model:get_total_count()
    local res, err = wdb:query("select count(id) as c from user")

    if err or not res or #res~=1 or not res[1].c then
        return 0
    else
        return res[1].c
    end
end


return user_model
