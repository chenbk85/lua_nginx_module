local x_headers = {organization_id='X-Organization-Id', user_id='X-User-Id', 
      last_name='X-User-Last-Name', first_name='X-User-First-Name',
      locale='X-Locale', timezone='X-Timezone', mail='X-Mail', role='X-Role'}

----------------------------
-- ユーティリティ関数
----------------------------
function split(str, delim)
    if string.find(str, delim) == nil then
        return { str }
    end

    local result = {}
    local pat = "(.-)" .. delim .. "()"
    local lastPos
    for part, pos in string.gfind(str, pat) do
        table.insert(result, part)
        lastPos = pos
    end
    table.insert(result, string.sub(str, lastPos))
    return result    
end


function add_header(key, str)
    local header = x_headers[key]
    if string.sub(str, 1, 1) == '"' then
        str = string.sub(str, 2, string.len(str)-1)
    end
    debug_log(header .. ": " .. str)
    ngx.var[key] = str
end


function debug_log(str)
    if ngx.var.debug == "true" then
        ngx.log(ngx.STDERR, str)
    end
end


-- 認証用 Cookie が存在するか？

local headers = ngx.req.get_headers()

if ngx.var.debug == "true" then
    local h_str = "Request Header => "
    for key, val in pairs(headers) do
        h_str = h_str .. key .. ":" .. val .. "; "
    end
    ngx.log(ngx.STDERR, h_str)
end

if headers["Cookie"] == nil then headers["Cookie"]="" end
local auth_ticket = headers["Cookie"]:match(ngx.var.auth_cookie..".-;")

if auth_ticket == nil then
   ngx.log(ngx.STDERR, "No Auth Cookie!!")
   return ngx.redirect(ngx.var.redirect_url)
end

-- 認証チケットの取り出し
auth_ticket = string.sub(auth_ticket, string.len(ngx.var.auth_cookie)+2)
debug_log("AuthTicket:" .. auth_ticket)

-- キャッシュのチェック ($auth_cache_time秒)
local users = ngx.shared.users
users:flush_expired(0)
local user = users:get(auth_ticket)

if user == nil then
   local res = ngx.location.capture("/auth/me")
   if string.match(res.body, "invalid_cookie_ticket") then
     ngx.log(ngx.STDERR, "Invalid Auth Cookie!!")
     return ngx.redirect(ngx.var.redirect_url)
   end
   debug_log(res.body)
   users:set(auth_ticket, res.body, ngx.var.auth_cache_time)
   user = res.body
else
   debug_log("** cache hit **: " .. user)
end


-- ヘッダに情報を埋め込む
local json_item = ""
local val

for key, header in pairs(x_headers) do
    json_item = string.match(user, tostring(key)..".-,")
    val = split(string.sub(json_item, 1, string.len(json_item)-1), ":")
    add_header(key, val[2])
end


-- 認可チェックが必要か？

if ngx.ctx.authenticate ~= true then
   return
end


-- 認可チェック
local permissions = ngx.shared.permissions
permissions:flush_expired(0)
local perm = permissions:get(auth_ticket)

if perm == nil then
   local url = "/auth/policy/permission?"
   if ngx.ctx.service_class ~= nil then 
     url = url.."service_class="..ngx.ctx.service_class
   end
   if ngx.ctx.service_rank ~= nil then
     url = url.."&service_rank="..ngx.ctx.service_rank
   end
   if ngx.ctx.serial_check == true then
     local serial = headers["Cookie"]:match(ngx.var.device_header..".-;")
     if serial ~= nil then
       ngx.log(ngx.STDERR, "Serial: "..serial)
       url = url.."&serial_id="..serial
     end
   end
   debug_log("URL:"..url)
   local p_res = ngx.location.capture(url)
   if string.match(p_res.body, "false") then
     ngx.log(ngx.STDERR, "Permission False!!")
     return ngx.redirect(ngx.var.redirect_url)
   end
   debug_log(p_res.body)
   permissions:set(auth_ticket, p_res.body, ngx.var.permission_cache_time)
   perm = p_res.body
else
   debug_log("** cache hit **: " .. perm)
end







