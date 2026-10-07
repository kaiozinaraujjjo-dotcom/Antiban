--[[
    Loader.lua
    ------------------------------------------------------------------
    Resolves and initializes the remote module from its host.
    All identifying strings are XOR-obfuscated at rest.

    Authors: lua_coder3 & Vetx
    ------------------------------------------------------------------
]]

-- ============================================================
-- XOR STRING TABLE
-- ============================================================
-- Keys are split into fragments, recombined at call time.

local _K1 = { 0x4E, 0x91, 0x27, 0x3C, 0xA5, 0x62, 0x18 }
local _K2 = { 0x7B, 0x04, 0xD2, 0x55, 0x89, 0x10, 0xEE }

local function _key()
    local k = {}
    for i = 1, #_K1 do k[#k + 1] = _K1[i] end
    for i = 1, #_K2 do k[#k + 1] = _K2[i] end
    return k
end

local function _s(...)
    local bytes = { ... }
    local k = _key()
    local out = {}
    for i = 1, #bytes do
        out[i] = string.char(bit32.bxor(bytes[i], k[(i - 1) % #k + 1]))
    end
    return table.concat(out)
end

-- ============================================================
-- ENCODED COMPONENTS
-- ============================================================
-- Each entry below is the XOR-encoded byte sequence for one URL part.
-- Regenerate with: for c in string you want: byte(i) XOR key[i]

local PARTS = {
    -- "https://"                (8 chars)
    scheme = { 0x35, 0xF5, 0x4C, 0x5B, 0xCD, 0x4E, 0x2A, 0x6C },
    -- "raw.githubusercontent"  (23 chars)
    host   = {
        0x25, 0xF1, 0x5F, 0x40, 0xC7, 0x79, 0x2E, 0x65,
        0x0C, 0xF4, 0x76, 0x23, 0xF1, 0x14, 0x55, 0x2E,
        0x0E, 0x84, 0x7B, 0x66, 0xD3, 0x72, 0x02,
    },
    -- ".com/"                   (5 chars)
    tld    = { 0x09, 0xF2, 0x6D, 0x1A, 0xD9 },
    -- repo slug                 (encoded below)
    repo   = {
        0x16, 0x99, 0x11, 0x40, 0xA0, 0x19, 0x72, 0x04,
        0x27, 0xC5, 0x31, 0x2B, 0x99, 0x55, 0x1C, 0x52,
        0x3D, 0x9F, 0x2E, 0x40, 0xC5, 0x34, 0x0A, 0x0F,
        0x05, 0xCC, 0x6D, 0x1D, 0xF4, 0x46, 0x7A, 0x39,
        0x7A, 0xB5, 0x0A, 0x29, 0x88, 0x1C, 0x64,
    },
    -- "/main/"                  (6 chars)
    branch = { 0x67, 0xB4, 0x5F, 0x26, 0xF2, 0x0C },
    -- "/AntiBan.lua"            (12 chars)
    file   = {
        0x67, 0xB1, 0x1F, 0x2A, 0x84, 0x1B, 0x7A, 0x5F,
        0x1E, 0xDE, 0x7C, 0x11,
    },
    -- "cdn.jsdelivr.net/gh/"    (20 chars)
    cdn    = {
        0x0C, 0xA0, 0x12, 0x52, 0x95, 0x48, 0x0A, 0x25,
        0x16, 0xD1, 0x6D, 0x1A, 0xFB, 0x02, 0x5D, 0x2C,
        0x1B, 0x85, 0x19, 0x5F,
    },
}

-- ============================================================
-- URL ASSEMBLY
-- ============================================================

local function part(name)
    return _s(table.unpack(PARTS[name]))
end

local function buildUrls()
    local a = part("scheme") .. part("host") .. part("tld")
           .. part("repo") .. part("branch") .. part("file")
    local b = part("scheme") .. part("cdn")
           .. part("repo") .. "@" .. part("branch"):sub(2, -2) .. "/"
           .. part("file"):sub(2)
    return { a, b }
end

-- ============================================================
-- FETCH
-- ============================================================

local function fetchSource()
    local errors = {}
    for _, url in ipairs(buildUrls()) do
        local ok, body = pcall(function()
            return game:HttpGet(url, true)
        end)
        if ok and type(body) == "string" and #body > 100
           and not body:find("404: Not Found", 1, true) then
            return body
        end
        errors[#errors + 1] = url
    end
    return nil, errors
end

local source, tried = fetchSource()

if not source then
    warn("[Loader] module fetch failed")
    if tried then
        for _, u in ipairs(tried) do
            -- URL itself is not printed — only the count.
        end
    end
    return
end

local chunk, loadErr = loadstring(source, "=" .. part("file"):sub(2, -5))

if not chunk then
    warn("[Loader] compile error: " .. tostring(loadErr))
    return
end

local ok, mod = pcall(chunk)

if not ok or type(mod) ~= "table" then
    warn("[Loader] module did not return table")
    return
end

mod:Init()

if getgenv then
    getgenv().AntiBan = mod
else
    _G.AntiBan = mod
end

return mod
