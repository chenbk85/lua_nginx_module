local x_headers = {organization_id='X-Organization-Id', user_id='X-User-Id', 
      last_name='X-User-Last-Name', first_name='X-User-First-Name',
      locale='X-Locale', timezone='X-Timezone', mail='X-Mail', role='X-Role', uuid='X-UUID'}

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
if headers["Authorization"] == nil then headers["Authorization"]="" end

-- 認証チケットの取り出し
local auth_ticket = string.match(headers["Cookie"], ngx.var.auth_cookie.."=(.+)")
debug_log("AuthTicket:" .. tostring(auth_ticket))

-- OAuthトークンの取り出し
local oauth_token = string.match(headers["Authorization"], "OAuth (.+)")
debug_log("OAuthToken:" .. tostring(oauth_token))

-- 認証チケットがなく,OAuthトークンもなければ,ログインURLへリダイレクト
if ((auth_ticket == nil) and (oauth_token == nil)) then
   ngx.log(ngx.STDERR, "No Auth Cookie and OAuth Token!!")
   return ngx.redirect(ngx.var.redirect_url)
end

-- キャッシュのチェック ($auth_cache_time秒)
local cookies = ngx.shared.cookies
cookies:flush_expired(0)
local user = cookies:get(auth_ticket)

if user == nil then
   local res = ngx.location.capture("/auth/policy/me")
   if string.match(res.body, "invalid_cookie_ticket") then
     ngx.log(ngx.STDERR, "Invalid Auth Cookie!!")
     return ngx.redirect(ngx.var.redirect_url)
   end
   debug_log(res.body)
   cookies:set(auth_ticket, res.body, 5)
   user = res.body
else
   debug_log("** cache hit **: " .. user)
end

-- JSONパーサー
local response_json = Json.Decode(user)

-- 権限(scope)チェック
local scope_json = response_json["scope"]
local target_json = scope_json["target"]

debug_log("url_path: "..ngx.var.uri)
debug_log("method: "..ngx.var.request_method)

local matched_flag = false
for idx, v in pairs(target_json) do
    debug_log("uri: "..ngx.var.uri)
    debug_log("service_uri: "..v["service_uri"])
    if string.match(ngx.var.uri,v["service_uri"]) then
       debug_log("matched!")
       matched_flag = true
       break
    end
end


-- マッチしなければリダイレクション
if matched_flag==false then
       debug_log("mis_match! redirect to login_page")
       return ngx.redirect(ngx.var.redirect_url)
end

-- ヘッダに情報を埋め込む
local user_json = response_json["user"]
local val = ""
for key, header in pairs(x_headers) do
    if type(user_json[key])=="table" then
       val = table.concat(user_json[key],",")
    else
       debug_log("string_key: "..tostring(key))
       val = user_json[key]
    end
    debug_log(x_headers[key] .. ": " .. tostring(val))
    ngx.var[key] = val
end

return