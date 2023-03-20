config_log = "on"
config_log_path = "/usr/local/openresty/nginx/logs/"
config_rule_path = "/usr/local/openresty/nginx/conf/waf/rule/"
error_html=[[
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="Content-Language" content="zh-cn" />
    <title>Web应用防火墙</title>
  </head>
  <body>
    <h1 align="center"> 检测入侵,请求终止,ip:ipreplace </h1>
    <h5 align="center"><a href="https://www.yiwugo.com">返回义乌购</a> </h5>
  </body>
</html>
]]
