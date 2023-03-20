if check_white_ip() then
elseif check_white_ua() then
--elseif check_black_ua() then
elseif check_query() then
elseif check_post_args() then
--elseif check_cookie() then   
elseif check_cc(10, 60) then 
else
    return
end
