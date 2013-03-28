local x_headers = {organization_id='X-Organization-Id', user_id='X-User-Id', 
      last_name='X-User-Last-Name', first_name='X-User-First-Name',
      locale='X-Locale', timezone='X-Timezone', mail='X-Mail', role='X-Role', uuid='X-UUID'}

----------------------------
-- ユーティリティ関数
----------------------------
function debug_log(str)
    if ngx.var.debug == "true" then
        ngx.log(ngx.STDERR, str)
    end
end

----------------------------
-- 認証・認可チェック
----------------------------

-- 認証用 Cookie が存在するか？
local headers = ngx.req.get_headers()

if ngx.var.debug == "true" then
    local h_str = "Request Header => "
    for key, val in pairs(headers) do
        h_str = h_str .. key .. ":" .. val .. "; "
    end
    ngx.log(ngx.STDERR, h_str)
end

-- 認証チケットがなく,OAuthトークンもなければ,ログインURLへリダイレクト
if ((headers["Cookie"] == nil) and (headers["Authorization"] == nil)) then
   ngx.log(ngx.STDERR, "No Auth Cookie and OAuth Token!!")
   return ngx.redirect(ngx.var.redirect_url)
end

local res_context = nil
local cache = nil
local cache_key = nil

local request_uri = ngx.var.uri
-- ngx.var.req_uri = ngx.var.uri
debug_log("RequestUri:" .. tostring(request_uri))
-- debug_log("ngx.var.req_uri:" .. tostring(ngx.var.req_uri))

local request_method = ngx.var.request_method
-- ngx.var.req_method = ngx.var.request_method
debug_log("RequestMethod:" .. tostring(request_method))
-- debug_log("ngx.var.req_method:" .. tostring(ngx.var.req_method))

-- 認証チケットがある場合(認可チケットがある場合も認証チケットを優先)
if headers["Cookie"] then

   -- 認証チケットの取り出し
   local auth_ticket = string.match(headers["Cookie"], ngx.var.auth_cookie.."=(.+)")
   debug_log("AuthTicket:" .. tostring(auth_ticket))

   -- キャッシュのチェック ($auth_cache_time秒)
   if auth_ticket then
      cache_key = ngx.encode_base64(auth_ticket..","..request_uri..","..request_method)
      debug_log("CacheKey:" .. tostring(cache_key))

      cache = ngx.shared.auth_cache
      cache:flush_expired(0)
      res_context = cache:get(cache_key)
   else
      ngx.log(ngx.STDERR, "Invalid Request")
      return ngx.redirect(ngx.var.redirect_url)
   end

else
-- OAuthトークンしかない場合

   -- OAuthトークンの取り出し
   local oauth_token = string.match(headers["Authorization"], "OAuth (.+)")
   debug_log("OAuthToken:" .. tostring(oauth_token))

   -- キャッシュのチェック ($auth_cache_time秒)
   if oauth_token then
      cache_key = ngx.encode_base64(oauth_token..","..request_uri..","..request_method)
      cache = ngx.shared.auth_cache
      cache:flush_expired(0)
      res_context = cache:get(cache_key)
   else
      ngx.log(ngx.STDERR, "Invalid Request")
      return ngx.redirect(ngx.var.redirect_url)
   end
end


-- 権限情報の取得
if res_context == nil then
   ngx.log(ngx.STDERR, "[auth_agent][uri]:" .. ngx.var.uri)
   ngx.log(ngx.STDERR, "[auth_agent][method]:" .. ngx.var.request_method)
   local res = ngx.location.capture("/auth/policy/agent",{ vars = { x_req_uri = ngx.var.uri, x_req_method = ngx.var.request_method }} )
   if string.match(res.body, "invalid_cookie_ticket") then
      ngx.log(ngx.STDERR, "Invalid Auth Cookie!!")
      return ngx.redirect(ngx.var.redirect_url)
   end

   if string.match(res.body, "auth.oauth_invalid_access_token") then
      ngx.log(ngx.STDERR, "Invalid OAuth Token!!")
      return ngx.redirect(ngx.var.redirect_url)
   end

   debug_log(res.body)
   cache:set(cache_key, res.body, ngx.var.auth_cache_time)
   res_context = res.body
else
   debug_log("** cache hit **: " .. res_context)
end

-- JSONパーサー
local response_json = Json.Decode(res_context)

-- 権限(scope)チェック
local decision = response_json["result"]["decision"]
debug_log("decision:" .. decision)

local matched_flag = false

-- decisionがpermitでなければリダイレクション
if decision ~= "permit" then
       debug_log("access denied. redirect to login_page")
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