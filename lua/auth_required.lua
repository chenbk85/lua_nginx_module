-- ヘッダをログに残す
local h_str = "Request Header => "
local headers = ngx.req.get_headers()
for key, val in pairs(headers) do
    h_str = h_str .. key .. ":" .. val .. "; "
end

ngx.log(ngx.STDERR, h_str)

-- 認証用 Cookie が存在するか？
if headers["Cookie"] == nil then headers["Cookie"]="" end

local auth_ticket = string.match(headers["Cookie"], "iPlanetDirectoryPro.-;")

if auth_ticket == nil then
   ngx.header["Location"] = ngx.var.login_url
   ngx.log(ngx.STDERR, "No Auth Cookie!!")
   ngx.exit(ngx.HTTP_MOVED_PERMANENTLY)
end

-- 認証チケットの取り出し
auth_ticket = string.sub(auth_ticket, 21)
ngx.log(ngx.STDERR, "AuthTicket:" .. auth_ticket)

-- キャッシュのチェック (60秒)
local users = ngx.shared.users
users:flush_expired(0)
local user = users:get(auth_ticket)

if user == nil then
   local res = ngx.location.capture("/auth/me")
   ngx.log(ngx.STDERR, res.body)
   users:set(auth_ticket, res.body, 60)
else
   ngx.log(ngx.STDERR, "** cache hit **: " .. user)
end


