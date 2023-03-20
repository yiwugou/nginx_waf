### 该插件依赖openresty,具体安装方法网上找找

### 复制nginx_waf/* 到 /usr/local/openresty/nginx/conf/waf/*

### 在 nginx.conf 的 http 段添加
```
lua_package_path "/usr/local/openresty/lualib/?.lua;/usr/local/openresty/nginx/conf/waf/?.lua";
lua_shared_dict limit_cache 50m;
init_by_lua_file  /usr/local/openresty/nginx/conf/waf/init.lua; 
```
### 在 server 或者 location 中加
```
access_by_lua_file /usr/local/openresty/nginx/conf/waf/waf.lua; 

or

access_by_lua '
    if check_white_ip() then
    elseif check_white_ua() then
    elseif check_black_ua() then
    elseif check_query() then
    elseif check_post_args() then
    elseif check_cookie() then   
    elseif check_cc(10, 60) then 
    else
        return
    end
';
```

### 注意

##### 1.在windows系统中 如果修改了rule下面的文件 记得到linux中转换 :set ff=unix
