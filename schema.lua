local typedefs = require "kong.db.schema.typedefs"

return {
    name = "kong-plugin-icap",
    fields = {
        { protocols = typedefs.protocols },
        { config = {
            type = "record", 
            fields = {
                { icap_host = typedefs.host({ required = true }), },
                { icap_port = typedefs.port({ required = true }), },
                { icap_service = { type = "string", required = true}, },
                { timeout = { type = "number", default = 10000 }, },
                { keepalive = { type = "number", default = 60000 }, },
                
                { content_to_scan = { type = "array", required = true, default = {"text/plain",
                "multipart/form-data", 
                "application/x-www-form-urlencoded", 
                "application/pdf", 
                "application/zip", 
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "application/vnd.ms-excel",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document", 
                "application/msword", 
                "application/octet-stream"}, elements = { type = "string"}, }, },
                { tls = { type = "boolean", required = true, default = false }, },
                { tls_sni = { type = "string", required = false}, },                
            },
        }, },
    }
}
