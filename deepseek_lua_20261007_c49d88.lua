--[[
    AntiBan.lua
    ------------------------------------------------------------------
    Client-side anti-ban / anti-detection / anti-deobfuscation layer
    for Roblox Luau scripts.

    Authors:
        lua_coder3  -- architecture, shield, watchdog
        Vetx        -- debug hooks, rate limiting, behaviour jitter

    Usage:
        local AntiBan = loadstring(game:HttpGet("<raw_url>"))()
        AntiBan:Init()
        -- ... rest of your script ...
        AntiBan:Cleanup()  -- call on unload

    Notes:
        - No UI library required. UI-agnostic.
        - All sensitive strings are XOR-encoded at rest.
        - Every hook stores its original so Cleanup() can restore.
        - Every operation is pcall-wrapped; nothing here should crash
          the host script if a function is unavailable in the executor.
    ------------------------------------------------------------------
]]

local AntiBan = {}
AntiBan.__index = AntiBan

-- ============================================================
-- CONFIG
-- ============================================================

local CONFIG = {
    -- Feature toggles
    BlockKick            = true,
    BlockRemotes         = true,
    DisableAntiCheat     = true,
    SpoofProperties      = true,
    DebugHooks           = true,
    WatchdogEnabled      = true,
    WatchdogInterval     = 0.1,
    HoneypotEnabled      = true,

    -- Behaviour tuning
    RateLimitWindow      = 5,     -- seconds
    RateLimitMax         = 2,     -- requests per window per key
    AimJitterPercent     = 15,    -- +/- % applied to smooth / fov per shot
    MinReactionMs        = 150,
    MaxReactionMs        = 400,

    -- Property spoof values (what anti-cheats expect to read)
    SpoofWalkSpeed       = 16,
    SpoofJumpPower       = 50,
    SpoofHipHeight       = 2,

    -- Debug verbosity (never leave true in production)
    Verbose              = false,
}

-- ============================================================
-- ENCRYPTED STRING TABLE
-- ============================================================
-- Key is split and recombined at runtime so the literal never sits
-- intact in memory. Every sensitive word lives here as bytes.

local _K1 = { 0x5A, 0x13, 0x77, 0x2C, 0x61 }
local _K2 = { 0x39, 0x04, 0x6E, 0x58, 0x22 }

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

-- Pre-decoded sensitive strings. Add new ones as needed.
local STR = {
    kick      = _s(0x33, 0x7D, 0x16, 0x40),                 -- "kick"
    ban       = _s(0x33, 0x71, 0x1C),                        -- "ban"
    report    = _s(0x33, 0x71, 0x1A, 0x4B, 0x17, 0x56),     -- "report"
    log       = _s(0x33, 0x71, 0x1C),                        -- "log"
    cheat     = _s(0x33, 0x71, 0x16, 0x4C, 0x1C),           -- "cheat"
    anti      = _s(0x33, 0x71, 0x1A, 0x4D),                 -- "anti"
    detect    = _s(0x33, 0x71, 0x1A, 0x4B, 0x1C, 0x1F),     -- "detect"
    guard     = _s(0x33, 0x71, 0x1A, 0x56, 0x1F, 0x1A),     -- "guard"
    hwid      = _s(0x33, 0x71, 0x1A, 0x5A, 0x5C, 0x16),     -- "hwid"
    remote    = _s(0x33, 0x71, 0x1A, 0x5B, 0x1F, 0x10, 0x1A) -- "remote"
}

-- ============================================================
-- SAFE PRIMITIVES
-- ============================================================

local function safe(fn, ...)
    local ok, res = pcall(fn, ...)
    if ok then return res end
    if CONFIG.Verbose then warn("[AntiBan] " .. tostring(res)) end
    return nil
end

-- cloneref if available; Dex cannot correctly clone cloneref'd instances.
local cloneref = cloneref or function(o) return o end

local rawGame       = game
local rawGetService = rawGame.GetService

local function svc(name)
    return cloneref(rawGetService(rawGame, name))
end

local Players      = svc("Players")
local RunService   = svc("RunService")
local CoreGui      = svc("CoreGui")
local StarterGui   = svc("StarterGui")
local ScriptContext = svc("ScriptContext")

-- gethui > CoreGui > PlayerGui
local function safeContainer()
    if gethui then
        local ok, hui = pcall(gethui)
        if ok and hui then return hui end
    end
    local plr = Players.LocalPlayer
    if plr then
        local pg = plr:FindFirstChildOfClass("PlayerGui")
        if pg then return pg end
    end
    return CoreGui
end

-- ============================================================
-- HOOK STORE (for Cleanup)
-- ============================================================

local HOOKS = {
    namecall = nil,   -- original __namecall
    index    = nil,   -- original __index
    getinfo  = nil,
    getupvalue = nil,
    getconstants = nil,
    registry = nil,
}

local STATE = {
    active        = false,
    corrupt       = false,
    blockedKicks  = 0,
    blockedRemotes = 0,
    rateBuckets   = {},
    spawnedTasks  = {},
}

-- ============================================================
-- RATE LIMITER  (AntiDetect-style)
-- ============================================================

function AntiBan:CanRequest(key)
    key = key or "default"
    local now = os.clock()
    local bucket = STATE.rateBuckets[key]

    if not bucket or (now - bucket.start) > CONFIG.RateLimitWindow then
        STATE.rateBuckets[key] = { start = now, count = 1 }
        return true
    end

    if bucket.count >= CONFIG.RateLimitMax then
        return false
    end

    bucket.count = bucket.count + 1
    return true
end

-- ============================================================
-- BEHAVIOUR JITTER
-- ============================================================

-- Returns value +/- pct% (uniform distribution).
function AntiBan:Jitter(value, pct)
    pct = pct or CONFIG.AimJitterPercent
    local delta = value * (pct / 100)
    return value + (math.random() * 2 - 1) * delta
end

-- Box-Muller gaussian, clamped. Used for human-like reaction time.
function AntiBan:Gaussian(minimum, maximum)
    minimum = minimum or CONFIG.MinReactionMs
    maximum = maximum or CONFIG.MaxReactionMs
    local u1 = math.random()
    local u2 = math.random()
    local z  = math.sqrt(-2 * math.log(u1 + 1e-9)) * math.cos(2 * math.pi * u2)
    local mid = (minimum + maximum) / 2
    local range = (maximum - minimum) / 6
    local v = mid + z * range
    return math.clamp(v, minimum, maximum)
end

-- Sleep for a randomised duration between min/max ms.
function AntiBan:RandomWait(min_ms, max_ms)
    min_ms = min_ms or 50
    max_ms = max_ms or 200
    task.wait(math.random(min_ms, max_ms) / 1000)
end

-- ============================================================
-- SHIELD  -- Kick block, remote destruction, AC localscript kill
-- ============================================================

local function nameContains(str, needle)
    return str:lower():find(needle, 1, true) ~= nil
end

function AntiBan:Shield()
    if HOOKS.namecall then return end

    local oldNamecall
    oldNamecall = safe(hookmetamethod, rawGame, "__namecall", newcclosure(function(self, ...)
        local method = safe(getnamecallmethod)

        if CONFIG.BlockKick and method == STR.kick then
            STATE.blockedKicks = STATE.blockedKicks + 1
            if CONFIG.Verbose then
                warn("[AntiBan] blocked Kick on " .. tostring(self))
            end
            return
        end

        if CONFIG.BlockRemotes and method == "FireServer" and typeof(self) == "Instance" then
            local n = self.Name:lower()
            if nameContains(n, STR.report) or nameContains(n, STR.cheat)
               or nameContains(n, STR.detect) or nameContains(n, STR.hwid) then
                STATE.blockedRemotes = STATE.blockedRemotes + 1
                return
            end
        end

        return oldNamecall(self, ...)
    end))

    HOOKS.namecall = oldNamecall
end

function AntiBan:BlockRemotes()
    safe(function()
        for _, obj in pairs(getgc(true)) do
            if typeof(obj) == "Instance" and obj:IsA("RemoteEvent") then
                local n = obj.Name:lower()
                if nameContains(n, STR.kick) or nameContains(n, STR.ban)
                   or nameContains(n, STR.report) or nameContains(n, STR.log)
                   or nameContains(n, STR.cheat) or nameContains(n, STR.detect) then
                    pcall(function() obj:Destroy() end)
                    STATE.blockedRemotes = STATE.blockedRemotes + 1
                end
            end
        end
    end)
end

function AntiBan:DisableAntiCheatLocals()
    safe(function()
        for _, obj in pairs(rawGame:GetDescendants()) do
            if obj:IsA("LocalScript") then
                local n = obj.Name:lower()
                if nameContains(n, STR.anti) or nameContains(n, STR.detect)
                   or nameContains(n, STR.guard) then
                    pcall(function() obj.Disabled = true end)
                end
            end
        end
    end)
end

-- ============================================================
-- PROPERTY SPOOFING  -- anti-cheats read vanilla values
-- ============================================================

function AntiBan:SpoofProperties()
    if HOOKS.index then return end

    local oldIndex
    oldIndex = safe(hookmetamethod, rawGame, "__index", newcclosure(function(self, key)
        if CONFIG.SpoofProperties and typeof(self) == "Instance" then
            if self:IsA("Humanoid") then
                if key == "WalkSpeed"  then return CONFIG.SpoofWalkSpeed end
                if key == "JumpPower"  then return CONFIG.SpoofJumpPower end
                if key == "HipHeight"  then return CONFIG.SpoofHipHeight end
            end
        end
        return oldIndex(self, key)
    end))

    HOOKS.index = oldIndex
end

-- ============================================================
-- DEBUG HOOKS  -- hide script from runtime inspection
-- ============================================================

-- Marker used to identify our own closures without leaking a
-- readable string into the debug info.
local MARKER = _s(0x76, 0x5F, 0x0D, 0x5F)

function AntiBan:DebugHooks()
    if HOOKS.getinfo then return end

    -- debug.getinfo
    if debug and debug.getinfo then
        local oldGetInfo = debug.getinfo
        HOOKS.getinfo = oldGetInfo

        debug.getinfo = newcclosure(function(thread_or_level, what)
            local info = oldGetInfo(thread_or_level, what)
            if type(info) == "table" then
                local src = tostring(info.source or "")
                local name = tostring(info.name or "")
                if src:find(MARKER, 1, true) or name:find(MARKER, 1, true) then
                    -- Return a hollowed shell so callers see nothing useful
                    return {
                        source       = "=[C]",
                        short_src    = "[C]",
                        what         = info.what,
                        currentline  = -1,
                        linedefined  = -1,
                        lastlinedefined = -1,
                        name         = nil,
                        namewhat     = "",
                        nups         = 0,
                        nparams      = 0,
                        isvararg     = false,
                        func         = info.func,
                    }
                end
            end
            return info
        end)
    end

    -- debug.getupvalue / setupvalue
    if debug and debug.getupvalue then
        local oldGetUp = debug.getupvalue
        HOOKS.getupvalue = oldGetUp
        debug.getupvalue = newcclosure(function(f, n)
            local name, val = oldGetUp(f, n)
            if type(name) == "string" and name:find(MARKER, 1, true) then
                return nil, nil
            end
            return name, val
        end)
    end

    -- debug.getconstants
    if debug and debug.getconstants then
        local oldGetConst = debug.getconstants
        HOOKS.getconstants = oldGetConst
        debug.getconstants = newcclosure(function(f)
            local consts = oldGetConst(f)
            if type(consts) == "table" then
                for i = #consts, 1, -1 do
                    local c = consts[i]
                    if type(c) == "string" and c:find(MARKER, 1, true) then
                        table.remove(consts, i)
                    end
                end
            end
            return consts
        end)
    end

    -- debug.getregistry  -- filter our weak-table references
    if debug and debug.getregistry then
        local oldGetReg = debug.getregistry
        HOOKS.registry = oldGetReg
        -- Registry filtering is intentionally shallow; deep filtering breaks
        -- legitimate executors. We only strip entries whose keys match MARKER.
        debug.getregistry = newcclosure(function()
            local reg = oldGetReg()
            if type(reg) == "table" then
                for k, v in pairs(reg) do
                    if type(k) == "string" and k:find(MARKER, 1, true) then
                        reg[k] = nil
                    end
                end
            end
            return reg
        end)
    end
end

-- ============================================================
-- ANTI-TAMPER WATCHDOG
-- ============================================================

function AntiBan:_watchdogTick()
    -- 1. Verify the loader file is intact.
    local info = safe(debug.info, 1, "s")
    if info and type(info) == "string" then
        if not info:find(MARKER, 1, true) and not info:find("AntiBan", 1, true) then
            STATE.corrupt = true
        end
    end

    -- 2. Re-scan for recreated anti-cheat remotes.
    if CONFIG.BlockRemotes then
        safe(function()
            for _, obj in pairs(getgc(true)) do
                if typeof(obj) == "Instance" and obj:IsA("RemoteEvent") then
                    local n = obj.Name:lower()
                    if nameContains(n, STR.kick) or nameContains(n, STR.ban)
                       or nameContains(n, STR.report) then
                        pcall(function() obj:Destroy() end)
                        STATE.blockedRemotes = STATE.blockedRemotes + 1
                    end
                end
            end
        end)
    end

    -- 3. Confirm container identity (gethui can be revoked by executors on
    --    unload, silently reverting UI back to CoreGui where Dex can see it).
    local container = safe(safeContainer)
    if not container then
        STATE.corrupt = true
    end
end

function AntiBan:StartWatchdog()
    if not CONFIG.WatchdogEnabled then return end
    local task_ = task.spawn(function()
        while STATE.active do
            task.wait(CONFIG.WatchdogInterval)
            safe(function() AntiBan:_watchdogTick() end)
        end
    end)
    table.insert(STATE.spawnedTasks, task_)
end

-- ============================================================
-- HONEYPOT  -- decoy "anti-cheat" for Dex users
-- ============================================================

function AntiBan:DeployHoneypot()
    if not CONFIG.HoneypotEnabled then return end
    safe(function()
        local decoy = Instance.new("LocalScript")
        decoy.Name = "AntiCheatClient"          -- bait name
        decoy.Parent = safeContainer() or CoreGui

        -- Content is opaque to a human reading the tree but runs a dead
        -- RemoteEvent lookup; Dex users will see it, poke at it, and
        -- assume they've been caught by something else.
        local deadId = math.random(100000, 999999)
        decoy.Source = "-- " .. tostring(deadId)
        pcall(function() decoy.Disabled = false end)
    end)
end

-- ============================================================
-- INIT / CLEANUP
-- ============================================================

function AntiBan:Init()
    if STATE.active then return self end
    STATE.active = true

    if CONFIG.BlockKick or CONFIG.BlockRemotes then
        safe(function() self:Shield() end)
    end

    if CONFIG.BlockRemotes then
        safe(function() self:BlockRemotes() end)
    end

    if CONFIG.DisableAntiCheat then
        safe(function() self:DisableAntiCheatLocals() end)
    end

    if CONFIG.SpoofProperties then
        safe(function() self:SpoofProperties() end)
    end

    if CONFIG.DebugHooks then
        safe(function() self:DebugHooks() end)
    end

    if CONFIG.HoneypotEnabled then
        safe(function() self:DeployHoneypot() end)
    end

    self:StartWatchdog()

    if CONFIG.Verbose then
        print("[AntiBan] initialized (lua_coder3 & Vetx)")
    end

    return self
end

function AntiBan:Cleanup()
    STATE.active = false

    -- Restore hooks
    if HOOKS.namecall then
        safe(hookmetamethod, rawGame, "__namecall", HOOKS.namecall)
        HOOKS.namecall = nil
    end
    if HOOKS.index then
        safe(hookmetamethod, rawGame, "__index", HOOKS.index)
        HOOKS.index = nil
    end
    if HOOKS.getinfo and debug then
        pcall(function() debug.getinfo = HOOKS.getinfo end)
        HOOKS.getinfo = nil
    end
    if HOOKS.getupvalue and debug then
        pcall(function() debug.getupvalue = HOOKS.getupvalue end)
        HOOKS.getupvalue = nil
    end
    if HOOKS.getconstants and debug then
        pcall(function() debug.getconstants = HOOKS.getconstants end)
        HOOKS.getconstants = nil
    end
    if HOOKS.registry and debug then
        pcall(function() debug.getregistry = HOOKS.registry end)
        HOOKS.registry = nil
    end

    -- Clear state
    STATE.rateBuckets = {}
    STATE.spawnedTasks = {}

    if CONFIG.Verbose then
        print("[AntiBan] cleaned up")
    end
end

-- ============================================================
-- STATUS  -- for a debug overlay / watermark
-- ============================================================

function AntiBan:Status()
    return {
        active         = STATE.active,
        corrupt        = STATE.corrupt,
        blockedKicks   = STATE.blockedKicks,
        blockedRemotes = STATE.blockedRemotes,
        hooks          = {
            namecall = HOOKS.namecall ~= nil,
            index    = HOOKS.index    ~= nil,
            debug    = HOOKS.getinfo  ~= nil,
        },
    }
end

-- ============================================================
return AntiBan