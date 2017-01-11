local sgsub = string.gsub
local tinsert = table.insert
local type = type
local ipairs = ipairs
local pairs = pairs
local cjson = require("cjson")
local utils = require("app.libs.utils")
local config = require("app.config.config")
local DB = {}





function DB:new(conf)
    conf = conf or config.pgsql
    local instance = {}
    instance.conf = conf
    setmetatable(instance, { __index = self})
    return instance
end

function DB:exec(sql)
    if not sql then
        ngx.log(ngx.ERR, "sql parse error! please check")
        return nil, "sql parse error! please check"
    end
    local pgsql = require("pgmoon")
    local pg = pgsql.new(config.w_pgsql)

    for i = 1, 3 do
        ok, err = pg:connect()
        if not ok then
            -- ngx.log(ngx.ERR, "failed to connect to database: ", err)
            ngx.sleep(0.01)
        else
            break
        end
    end

    if not ok then
        -- ngx.log(ngx.ERR, "fatal response due to query failures")
        -- return ngx.exit(500)
        return nil
    end

    -- the caller should ensure that the query has no side effects
    local res
    for i = 1, 2 do
        res, err = pg:query(sql)
        if not res then
            -- ngx.log(ngx.ERR, "failed to send query: ", err)
            ngx.sleep(0.01)
            ok, err = pg:connect()
            if not ok then
                -- ngx.log(ngx.ERR, "failed to connect to database: ", err)
                break
            end
        else
            break
        end
    end

    if not res then
        -- ngx.log(ngx.ERR, "fatal response due to query failures")
        -- return ngx.exit(500)
        return nil
    end

    pg:keepalive()
    -- local ok, err = pg:keepalive(0, 5)
    -- if not ok then
    --     ngx.log(ngx.ERR, "failed to keep alive: ", err)
    -- end

    pg = nil
    return res
end



function DB:query(sql, params)
    sql = self:parse_sql(sql, params)
    return self:exec(sql)
end

function DB:select(sql, params)
    return self:query(sql, params)
end

function DB:insert(sql, params)
    local res, err, errno, sqlstate = self:query(sql, params)
    if res and not err then
        return  res.insert_id, err
    else
        return res, err
    end
end

function DB:update(sql, params)
    return self:query(sql, params)
end

function DB:delete(sql, params)
    local res, err, errno, sqlstate = self:query(sql, params)
    if res and not err then
        return res.affected_rows, err
    else
        return res, err
    end
end

local function split(str, delimiter)
    if str==nil or str=='' or delimiter==nil then
        return nil
    end
    
    local result = {}
    for match in (str..delimiter):gmatch("(.-)"..delimiter) do
        tinsert(result, match)
    end
    return result
end


local function compose(t, params)
    if t==nil or params==nil or type(t)~="table" or type(params)~="table" or #t~=#params+1 or #t==0 then
        return nil
    else
        local result = t[1]
        for i=1, #params do
            result = result  .. params[i].. t[i+1]
        end
        return result
    end
end


function DB:parse_sql(sql, params)
    if not params or not utils.table_is_array(params) or #params == 0 then
        return sql
    end

    local new_params = {}
    for i, v in ipairs(params) do
        if v and type(v) == "string" then
            v = ngx.quote_sql_str(v)
        end
        
        tinsert(new_params, v)
    end

    local t = split(sql,"?")
    local sql = compose(t, new_params)

    return sql
end 

return DB
