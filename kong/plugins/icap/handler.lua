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
    VERSION = "0.2"
}


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
    kong.log.debug("Content-Type: " .. contentType)
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
        local rawBody, err = kong.request.get_raw_body()
        if not rawBody then 
            kong.response.exit(400, "Bad Request no raw body - error " .. err)
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
    local encapsStr = s_fmt(icapReq[3], tostring(encaps))

    t_rem(icapReq, 3)
    t_ins(icapReq, 3, encapsStr)

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

    kong.log.debug("icapProtocal config set")

    local icapReq = {
        [1] = "REQMOD " .. service .. " ICAP/1.0\r\n",
        [2] = "Host: " .. icapHost .. "\r\n", 
        [3] = "Encapsulated: req-hdr=0, req-body=%s\r\n", 
        [4] = "Allow: 204\r\n", 
        [5] = "X-Client-IP: " .. icapHost .. "\r\n", 
        [6] = "\r\n",

        [7] = "POST " .. "http://" .. host .. " HTTP/1.1\r\n",
        [8] = "\r\n",

        [9] = body_hex .. "\r\n",
        [10] = body,
        [11] = "\r\n",
        [12] = "0\r\n",
    }

    local icapReqMod = addEncaps(icapReq)

    return icapReqMod, host
end
-- Sends formatted icap request to icap server to be scanned and awaits response
local function sendReceiveICAP(conf, icapReq) 
    local icapHost = conf.icap_host 
    local icapPort = conf.icap_port 
    local timeout = conf.timeout 
    local keepalive = conf.keepalive
    kong.log.debug("sendReceiveICAP")
    kong.log.debug("Host: " .. icapHost)
    kong.log.debug("Port: " .. icapPort)

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

    for k, v in pairs(icapReq) do 
        local ok, err = sock:send(v)
        if not ok then 
            kong.log.err("failed to send: " .. v) 
	    kong.log.debug(err)
        end
    end

    local resp, err = sock:receiveany(10 * 1024)
    if not resp then 
        kong.response.exit(500, "Internal Server Error")
    end

    local ok, err = sock:setkeepalive() 
    if not ok then
      kong.log.err("failed to keepalive to ", icapHost, ":", tostring(icapPort), ": ", err)
      return nil, err
    end

    return resp
end
-- Handle response from the ICAP server
local function handleResp(resp, host)
    kong.log.debug("handleResp started")
    if resp ~= nil then 
        local codeStr = s_sub(resp, 10, 12) 
        local codeNum = tonumber(codeStr)

	kong.log.debug("ICAP response: " .. resp)

        if codeNum ~= 204 then 
            local msg = "ICAP " .. codeStr .. " " .. ICAP_RESPONSES[codeNum] .. " " .. host
            kong.ctx.shared.errmsg = msg 
            return kong.response.exit(400, msg)
        else 
            -- Status code 204 indicates no thread detected, do nothing and allow through the gateway
            return
        end
    else
        local msg = "ICAP No Response Data " .. host
        kong.ctx.shared.errmsg = msg 
        return kong.response.exit(500, "Internal Server Error")
    end
end

function KongICAPHandler:access(conf)
    local allowed, cType = contentAllowed(conf)
    kong.log.debug("Start ICAP")

    if allowed == true then 
        local body, mimetype = getPayloadData(conf, cType)
	kong.log.debug("Parse body")
        if type(body) == "table" then
	    kong.log.debug("type is table")
            for k,v in pairs(body) do 
                local icapReq, host = icapProtocol(conf, v)
                local resp = sendReceiveICAP(conf, icapReq)

                handleResp(resp, host)
            end
        else 
	    kong.log.debug("type is not table")
            local icapReq, host = icapProtocol(conf, body)
            local resp = sendReceiveICAP(conf, icapReq)

            handleResp(resp, host)
        end
    else
        return kong.response.exit(415, "Unsupported Media Type")
    end
end

return KongICAPHandler
