local http = require 'socket.http'
local base64 = require 'base64'
local openssl = {
    pkey = require 'openssl.pkey',
    digest = require 'openssl.digest',
    x509 = require 'openssl.x509',
    hmac = require 'openssl.hmac'
}
local ltn12 = require 'ltn12'
local cjson = require 'cjson'

local jwks_url = "http://keycloak:8080/realms/master/protocol/openid-connect/certs"
local cert_keys = {}

local function dump(o)
    if type(o) == 'table' then
        local s = '{ '
        for k, v in pairs(o) do
            if type(k) ~= 'number' then
                k = '"' .. k .. '"'
            end
            s = s .. '[' .. k .. '] = ' .. dump(v) .. ','
        end
        return s .. '} '
    else
        return tostring(o)
    end
end

if not config then
    config = {
        debug = true
    }
end

local function log(msg)
    if config.debug then
        core.Debug(tostring(msg))
    end
end

local function fetch_certs()
    local response_body = {}
    local res, code, response_headers = http.request {
        url = jwks_url,
        sink = ltn12.sink.table(response_body)
    }
    if code ~= 200 then
        core.Alert("Failed to fetch public keys from Keycloak")
        return nil
    end
    local jwks = table.concat(response_body)
    local parsed_jwks = cjson.decode(jwks)
    if not parsed_jwks or not parsed_jwks.keys then
        core.Alert("Invalid JWKS format")
        return nil
    end
    for _, key in ipairs(parsed_jwks.keys) do
        cert_keys[key.kid] = base64.decode(key.x5c[1])
    end
    return cert_keys
end

fetch_certs()

local function decodeJwt(authorizationHeader)
    local headerFields = core.tokenize(authorizationHeader, " .")

    if #headerFields ~= 4 then
        log("Improperly formated Authorization header. Should be 'Bearer' followed by 3 token sections.")
        return nil
    end

    if headerFields[1] ~= 'Bearer' then
        log("Improperly formated Authorization header. Missing 'Bearer' property.")
        return nil
    end

    --- print headerFields
    log('Decoded JWT header: ' .. dump(headerFields))

    local token = {}
    token.header = headerFields[2]
    log('Decoded JWT header: ' .. dump(token.header))
    token.headerdecoded = cjson.decode(base64.decode(token.header))

    token.payload = headerFields[3]
    token.payloaddecoded = cjson.decode(base64.decode(token.payload))

    token.signature = headerFields[4]
    token.signaturedecoded = base64.decode(token.signature)

    log('Decoded JWT header: ' .. dump(token.headerdecoded))
    log('Decoded JWT payload: ' .. dump(token.payloaddecoded))

    return token
end

local function setVariablesFromPayload(txn, decodedPayload)
    for key, value in pairs(decodedPayload) do
        txn:set_var("txn.oauth." .. key, dump(value))
    end
end

local function algorithmIsValid(token)
    if token.headerdecoded.alg == nil then
        log("No 'alg' provided in JWT header.")
        return false
    elseif token.headerdecoded.alg ~= 'HS256' and token.headerdecoded.alg ~= 'HS512' and token.headerdecoded.alg ~=
        'RS256' then
        log("HS256, HS512 and RS256 supported. Incorrect alg in JWT: " .. token.headerdecoded.alg)
        return false
    end

    return true
end

local function expirationIsValid(token)
    return os.difftime(token.payloaddecoded.exp, core.now().sec) > 0
end

local function rs256SignatureIsValid(token, cert)
    local digest = openssl.digest.new('SHA256')
    digest:update(token.header .. '.' .. token.payload)
    local certX509 = openssl.x509.new(cert)
    local publicKey = certX509:getPublicKey():tostring()
    local vkey = openssl.pkey.new(publicKey)
    local isVerified = vkey:verify(token.signaturedecoded, digest)
    return isVerified
end

local function jwtverify(txn)

    local kid
    local cert

    -- 1. Decode and parse the JWT
    local token = decodeJwt(txn.sf:req_hdr("Authorization"))

    if token == nil then
        log("Token could not be decoded.")
        goto out
    end

    -- Set an HAProxy variable for each field in the token payload
    setVariablesFromPayload(txn, token.payloaddecoded)

    -- 2. Verify the signature algorithm is supported (HS256, HS512, RS256)
    if algorithmIsValid(token) == false then
        log("Algorithm not valid.")
        goto out
    end

    kid = token.headerdecoded.kid
    if not cert_keys[kid] then
        cert_keys = fetch_certs() -- Atualiza as chaves públicas
    end

    cert = cert_keys[kid]
    if not cert then
        log("Cert key not found for kid: " .. kid)
        goto out
    end

    -- 3. Verify the signature with the certificate
    if token.headerdecoded.alg == 'RS256' then
        if rs256SignatureIsValid(token, cert) == false then
            log("Signature not valid.")
            goto out
        end
    end
    -- elseif token.headerdecoded.alg == 'HS256' then
    --     if hs256SignatureIsValid(token, hmacSecret) == false then
    --         log("Signature not valid.")
    --         goto out
    --     end
    -- elseif token.headerdecoded.alg == 'HS512' then
    --     if hs512SignatureIsValid(token, hmacSecret) == false then
    --         log("Signature not valid.")
    --         goto out
    --     end
    -- end

    -- 4. Verify that the token is not expired
    if expirationIsValid(token) == false then
        log("Token is expired.")
        goto out
    end

    -- 8. Set authorized variable
    log("req.authorized = true")
    txn.set_var(txn, "txn.authorized", true)

    -- exit
    do
        return
    end

    -- way out. Display a message when running in debug mode
    ::out::
    log("req.authorized = false")
    txn.set_var(txn, "txn.authorized", false)
end

-- Called on a request.
core.register_action('jwtverify', {'http-req'}, jwtverify, 0)
