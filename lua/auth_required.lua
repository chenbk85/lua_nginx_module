-- ヘッダをログに残す
local h_str = "Request Header => "
local headers = ngx.req.get_headers()
for key, val in pairs(headers) do
    h_str = h_str .. key .. ":" .. val .. "; "
end

local hoge = base64.enc("hogjfiojfafejawiofeja")
local hoge2 = base64.dec(hoge)

ngx.log(ngx.STDERR, h_str)
ngx.log(ngx.STDERR, "No Auth Cookie!!"..hoge)
ngx.log(ngx.STDERR, "No Auth Cookie2!!"..hoge2)
