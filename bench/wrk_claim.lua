-- every request carries a fresh nullifier so the load lands on postgres,
-- REPLAY_PERCENT of them repeat one this thread already claimed
--
--   docker run --rm --network aac_default -v "$PWD:/repo" \
--     -e NULLIFIER_TOKEN -e REPLAY_PERCENT=10 williamyeh/wrk \
--     -t4 -c48 -d30s --latency -s /repo/bench/wrk_claim.lua http://nullifier:8081

local HEX = "0123456789abcdef"
local REPLAY_PERCENT = tonumber(os.getenv("REPLAY_PERCENT") or "10")
local TOKEN = os.getenv("NULLIFIER_TOKEN") or ""

local next_id = 0

function setup(thread)
   thread:set("thread_id", next_id)
   next_id = next_id + 1
end

function init(args)
   math.randomseed(os.time() + thread_id * 7919)
   pool = {}
   pool_size = 0

   wrk.method = "POST"
   wrk.headers["Content-Type"] = "application/json"
   if TOKEN ~= "" then
      wrk.headers["Authorization"] = "Bearer " .. TOKEN
   end
end

local function random_nullifier()
   local out = {}
   for i = 1, 64 do
      local k = math.random(16)
      out[i] = HEX:sub(k, k)
   end
   return table.concat(out)
end

function request()
   local n
   if pool_size > 0 and math.random(100) <= REPLAY_PERCENT then
      n = pool[math.random(pool_size)]
   else
      n = random_nullifier()
      if pool_size < 50000 then
         pool_size = pool_size + 1
         pool[pool_size] = n
      end
   end
   return wrk.format(nil, "/claim", nil, '{"nullifiers":["' .. n .. '"]}')
end

function done(summary, latency, requests)
   io.write("\n")
   io.write(string.format("  throughput  %.0f req/s\n", summary.requests / (summary.duration / 1e6)))
   io.write(string.format("  errors      %d socket, %d non-200\n",
      summary.errors.connect + summary.errors.read + summary.errors.write + summary.errors.timeout,
      summary.errors.status))
   for _, p in ipairs({ 50, 90, 99, 99.9 }) do
      io.write(string.format("  p%-10s %.2f ms\n", p, latency:percentile(p) / 1000))
   end
end
