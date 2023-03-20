require 'config'
local optionIsOn = function (options) return options == "on" and true or false end


config_log = optionIsOn(config_log)

function read_rule(var)
    file = io.open(config_rule_path..'/'..var, "r")
    if file==nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end

attack_keyword = read_rule('attack_keyword')
black_ua = read_rule('black_ua')
white_ua = read_rule('white_ua')
white_ip = read_rule('white_ip')

function getClientIp()
    IP = ngx.req.get_headers()["X-Real-IP"]
    if IP == nil then
        IP  = ngx.req.get_headers()["X-Forwarded-For"] 
    end
    if IP == nil then
        IP  = ngx.var.remote_addr 
    end
    if IP == nil then
        IP  = "unknown"
    end
    return IP
end

function get_boundary()
    local header = ngx.req.get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = string.match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return string.match(header, ";%s*boundary=([^\",;]+)")
end

function write(logfile, msg)
    local fd = io.open(logfile, "ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end

function debug_print(line)
    local filename = config_log_path..'/'.."lua_debug.log"
    local newLine = tostring(line).."\n"
    write(filename, newLine)
end

function log(attackType, data, ruletag)
    if config_log then
        local realIp = getClientIp()
        local url = ngx.var.request_uri
        local ua = ngx.var.http_user_agent
        local servername = ngx.var.server_name
        local method = ngx.req.get_method()
        local time = ngx.localtime()
        if ua  then
            
        else
            ua = "-"
        end
        line = realIp..' ['..time..'] '..method..' '..servername..url..' "'..ua..'" '..attackType..' "'..data..'" "'..ruletag..'"\n'
        local filename = config_log_path..'/'..servername.."_"..ngx.today().."_waf.log"
        write(filename, line)
    end
end

function ipToDecimal(ckip)
    local n = 4
    local decimalNum = 0
    local pos = 0
    for s, e in function() return string.find(ckip, '.', pos, true) end do
        n = n - 1
        decimalNum = decimalNum + string.sub(ckip, pos, s-1) * (256 ^ n)
        pos = e + 1
        if n == 1 then decimalNum = decimalNum + string.sub(ckip, pos, string.len(ckip)) end
    end
    return decimalNum
end


function say_html()
    ngx.header.content_type = "text/html"
    local ht = string.gsub(error_html, 'ipreplace', getClientIp())
    ngx.say(ht)
    ngx.exit(200)
end

function check_attack_keyword(data, attackType)
    for _,rule in pairs(attack_keyword) do
        if rule ~="" and data~="" and ngx.re.match(ngx.unescape_uri(data), rule, "isjo") then
            log(attackType, data, rule)
            say_html()
            return true
        end
    end
    return false
end

function check_post_args()
    ngx.req.read_body()
    local args = ngx.req.get_post_args()
    if not args then
        return false
    end
    for key, val in pairs(args) do
        if key and type(key) ~= "boolean" and check_attack_keyword(key, 'post_args_key') then
            return true
        end
        if type(val) == "table" then
            if type(val[1]) == "boolean" then
                return false
            end
            data = table.concat(val, ", ")
        else
            data = val
        end
        if data and type(data) ~= "boolean" and check_attack_keyword(data, 'post_args_val') then
            return true
        end
    end
    return false
end

function check_query()
    local args = ngx.req.get_uri_args()
    for key, val in pairs(args) do
        if key and type(key) ~= "boolean" and check_attack_keyword(key, 'query_key') then
            return true
        end
        if type(val) == "table" then
            if type(val[1]) == "boolean" then
                return false
            end
            data = table.concat(val, ", ")
        else
            data = val
        end
        if data and type(data) ~= "boolean" and check_attack_keyword(data, 'query_val') then
            return true
        end
    end
    return false
end


function check_black_ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _,rule in pairs(black_ua) do
            if rule ~="" and ngx.re.match(ua, rule, "isjo") then
                log('ua', "-", rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function check_white_ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _,rule in pairs(white_ua) do
            if rule ~="" and ngx.re.match(ua, rule, "isjo") then
                return true
            end
        end
    end
    return false
end

function check_white_ip()
    if next(white_ip) ~= nil then
        local cIP = getClientIp()
        local numIP = 0
        if cIP ~= "unknown" then numIP = tonumber(ipToDecimal(cIP))  end
        for _,ip in pairs(white_ip) do
            local s, e = string.find(ip, '-', 0, true)
            if s == nil and cIP == ip then
                return true
            elseif s ~= nil then
                sIP = tonumber(ipToDecimal(string.sub(ip, 0, s - 1)))
                eIP = tonumber(ipToDecimal(string.sub(ip, e + 1, string.len(ip))))
                if numIP >= sIP and numIP <= eIP then
                   return true
                end
            end
        end
    end
    return false
end

function check_cookie()
    local ck = ngx.var.http_cookie
    if ck then
        for _,rule in pairs(attack_keyword) do
            if rule ~="" and ngx.re.match(ck, rule, "isjo") then
                log('cookie', ck, rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function check_cc(cc_count, cc_seconds, token)
    local limit_cache = ngx.shared.limit_cache
    local req,_ = limit_cache:get(token)
    if req then
        if req > cc_count then
            log('cc', "-", "cc")
            say_html()
            return true
        else
            limit_cache:incr(token, 1)
        end
    else
        limit_cache:set(token, 1, cc_seconds)
    end
    return false
end

function check_cc_ip(cc_count, cc_seconds)
    local token = getClientIp()
    return check_cc(cc_count, cc_seconds, token);
end

function check_cc_uri(cc_count, cc_seconds)
    local token = getClientIp()..'_'..ngx.var.uri
    return check_cc(cc_count, cc_seconds, token);
end

function check_scan_header() -- 常用扫描器
    if ngx.var.http_Acunetix_Aspect then
        ngx.exit(444)
        return true;
    end
    if ngx.var.http_X_Scan_Memo then
        ngx.exit(444)
        return true;
    end
end