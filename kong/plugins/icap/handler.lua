local kong = kong
local ngx = ngx
local var = ngx.var
local s_find = string.find
local s_gsub = string.gsub
local s_len = string.len
local s_fmt = string.format
local s_sub = string.sub
local t_rem = table.remove
local t_ins = table.insert

local KongICAPHandler = {
    PRIORITY = 2001,
    VERSION = "0.3"
}


-- Dump a JSON to a String
function dump(o)
    if type(o) == 'table' then
        local s = '{ '
        for k,v in pairs(o) do
            if type(k) ~= 'number' then k = '"'..k..'"' end
            s = s .. '['..k..'] = ' .. dump(v) .. ','
        end
        return s .. '} '
    else
        return tostring(o)
    end
end

local ICAP_RESPONSES = {
    [200] = "OK",
    [201] = "Created",
    [204] = "No modification needed", -- This is the only response allowed through the gateway 
    [206] = "Partial Content",
    [400] = "Bad request",
    [404] = "ICAP Service not found",
    [405] = "Method not allowed for service",
    [408] = "Request timeout",
    [418] = "Bad composition",
    [500] = "Server error",
    [501] = "Method not implemented",
    [502] = "Bad Gateway",
    [503] = "Service overloaded",
    [505] = "ICAP version not supported by server",
}
-- Checks content type returning true and the content-type if whitelisted. Note, if content type is multipart/form-data 
-- or x-www-form-urlencoded all attached media types will be scanned without checking against the whitelist.
local function contentAllowed(conf)
    local allowedContent = conf.content_to_scan

    local contentType = kong.request.get_header("Content-Type")
    if not contentType then 
        kong.response.exit(400, "Bad Request content type")
    end
    kong.log.notice("Content-Type: " .. contentType)
end
-- Checks content type returning true and the content-type if whitelisted. Note, if content type is multipart/form-data 
-- or x-www-form-urlencoded all attached media types will be scanned without checking against the whitelist.
local function contentAllowed(conf)
    local allowedContent = conf.content_to_scan

    local contentType = kong.request.get_header("Content-Type")
    if not contentType then 
        kong.response.exit(400, "Bad Request no content-type")
    end

    if s_find(contentType, "multipart/form-data", nil, true) or s_find(contentType, "application/x-www-form-urlencoded", nil, true) then
        return true, contentType
    else
        for _,v in ipairs(allowedContent) do 
            if contentType == v then 
                return true, contentType
            end
        end
    end

    return false, nil
end
-- Extracts file data from request payload.
local function getPayloadData(conf, contentType)
    if s_find(contentType, "multipart/form-data", nil, true) or s_find(contentType, "application/x-www-form-urlencoded", nil, true) then
        local body, err, mimetype = kong.request.get_body()
        if not body then 
            kong.response.exit(400, "Bad Request no body")
        end

        return body, mimetype 
    else
        kong.log.notice("kong.request.get_raw_body")
        local rawBody, err = kong.request.get_raw_body()
        
        if not rawBody then 
            kong.log.err("err: " .. err)
            kong.response.exit(400, "Bad Request no raw body - error " .. err)
        else
            kong.log.notice("getPayloadData: no error")
        end

        return rawBody, contentType
    end
end
-- Get byte offset of where request body begins
local function addEncaps(icapReq)
    local encaps = 0
    for i = 1, 6, 1 do 
        encaps = encaps + s_len(icapReq[i]) 
    end
    -- Assume that the byte offset of headers is a three digit number, add one
    encaps = encaps + 1
    local encapsStr = s_fmt(icapReq[5], tostring(encaps))

    t_rem(icapReq, 5)
    t_ins(icapReq, 5, encapsStr)

    return icapReq
end
-- Formats request to icap server according to icap protocol
local function icapProtocol(conf, body) 
    local icapHost = conf.icap_host 
    local service = conf.icap_service 

    local PathOnly
    if var.request_uri ~= nil then
        PathOnly = s_gsub(var.request_uri,"%?.*","")
    else
        kong.log.err("nginx request uri is nil")
    end

    local host = var.host .. PathOnly
    local body_length = s_len(body)
    local body_hex = s_fmt("%02x", body_length) 

    kong.log.notice("icapProtocal config set")

    local userAgent = kong.request.get_header("User-Agent")
    if not userAgent then
        userAgent = "Kong"
    end
    
    local contentLength = kong.request.get_header("Content-Length")
    if not contentLength then
        contentLength = "0"
    end
    
    -- TO DO: add all other Headers sent by the Consumer to Kong

    local icapReq = {
        [1] = "REQMOD icap://" .. icapHost .. "/" .. service .. " ICAP/1.0\r\n",
        [2] = "Host: " .. icapHost .. "\r\n", 
        [3] = "User-Agent: Kong\r\n",
        [4] = "Allow: 204\r\n", 
        [5] = "Encapsulated: req-hdr=0, req-body=%s\r\n", 
        [6] = "\r\n",

        [7] = "POST " .. "http://" .. host .. " HTTP/1.1\r\n",
        [8] = "User-Agent: " .. userAgent .. "\r\n",
        [9] = "Content-Length: " .. contentLength .. "\r\n",
        [10] = "\r\n",

        [11] = body_hex .. "\r\n",
        [12] = body,
        [13] = "\r\n",
        [14] = "0\r\n",

    }
-- [14] = "0; ieof\r\n\r\n",
    local icapReqMod = addEncaps(icapReq)

    return icapReqMod, host
end
-- Sends formatted icap request to icap server to be scanned and awaits response
local function sendReceiveICAP(conf, icapReq) 
    local icapHost = conf.icap_host 
    local icapPort = conf.icap_port 
    local timeout = conf.timeout 
    local keepalive = conf.keepalive
    kong.log.notice("sendReceiveICAP")
    kong.log.notice("Host: " .. icapHost)
    kong.log.notice("Port: " .. icapPort)

    local sock = ngx.socket.tcp()
    sock:settimeout(timeout)

    local ok, err = sock:connect(icapHost, icapPort)
    if not ok then 
        kong.log.err("failed to connect to ", icapHost, ":", tostring(icapPort), ": ", err)
    end

    if conf.tls then 
        ok, err = sock:sslhandshake(true, conf.tls_sni, false)
        if not ok then
            kong.log.err("failed to perform TLS handshake to ", icapHost, ":", tostring(icapPort), ": ", err)
            return
        end
    end

    local optionsICAP="OPTIONS icap://" .. conf.icap_host .. "/" .. conf.icap_service .. " ICAP/1.0\n" ..
    "Host: " .. conf.icap_host .. "\n" ..
    "User-Agent: Kong\n" ..
    "Encapsulated: null-body=0\n"
    optionsICAP = optionsICAP .. '\n'
    
    -- Send the OPTIONS request
    kong.log.notice("OPTIONS request: '" .. dump(optionsICAP) .. "'")
    local bytes, err = sock:send(optionsICAP)
    if err then
        kong.log.notice("failed to send OPTIONS: ", err)
        return
    end
    -- Receive the OPTIONS request
    -- local data, err, partial = sock:receive()
    local data, err = sock:receiveany(10 * 1024)
    if err then
        kong.log.notice("failed to receive OPTIONS: ", err)
        return
    end
    kong.log.notice("OPTIONS response is: ", data)

    -- Send the REQMOD request
    kong.log.notice("REQMOD request: '" .. dump(icapReq) .. "'")
    local ok, err = sock:send(icapReq)
    if err then
        kong.log.err("sock:send REQMOD - err: ", err)
        return
    else
        kong.log.notice("sock:send REQMOD no err")
    end
    if not ok then 
        kong.log.err("failed to send REQMOD - err: " .. err) 
        return
    end
    -- Receive the REQMOD request
    local data, err = sock:receiveany(10 * 1024)
    --local data, err, partial = sock:receive()
    if err then
        kong.log.err("failed to receive REQMOD - err: ", err)
        return
    else
        kong.log.notice("REQMOD no err")
        kong.log.notice("REQMOD response is: " .. data)
    end
    if not data then 
        return
    end

    -- CLose the socket
    sock:close()
    
    return data
end
-- Handle response from the ICAP server
local function handleResp(resp)
    kong.log.notice("handleResp started")
    local msg = {}
    
    if resp ~= nil then 
        local codeStr = s_sub(resp, 10, 12) 
        local codeNum = tonumber(codeStr)

	    if codeNum ~= 204 then 
            msg.error = "400"
            msg.message = "ICAP Code:" .. codeStr .. " Message:'" .. ICAP_RESPONSES[codeNum] .. "'"
            return kong.response.exit(400, msg)
        else 
            -- Status code 204 indicates no thread detected, do nothing and allow through the gateway
            return
        end
    else
        msg.error = "500"
        msg.message = "ICAP No Response Data"
    return kong.response.exit(500, msg)
    end
end

function KongICAPHandler:access(conf)
    kong.log.notice("Start ICAP")
    local resp
    local icapReq
    local host 
    local msg = {}

    local allowed, cType = contentAllowed(conf)
    
    if allowed == true then 
        local body, mimetype = getPayloadData(conf, cType)
	    kong.log.notice("Parse body")
        if type(body) == "table" then
	        kong.log.notice("type is table")
            for k,v in pairs(body) do 
                icapReq, host = icapProtocol(conf, v)
                resp = sendReceiveICAP(conf, icapReq)
            end
        else 
	        kong.log.notice("type is not table")
            icapReq, host = icapProtocol(conf, body)
            resp = sendReceiveICAP(conf, icapReq)
        end
    else
        msg.error = "415"
        msg.message = "Unsupported Media Type"

        return kong.response.exit(415, msg)
    end

    handleResp(resp, host)
    
end

return KongICAPHandler
