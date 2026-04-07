import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-worker-key",
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  // Authenticate worker
  const workerKey = req.headers.get("x-worker-key");
  const expectedKey = Deno.env.get("WORKER_API_KEY");
  if (!expectedKey || workerKey !== expectedKey) {
    return json({ error: "Unauthorized" }, 401);
  }

  // Service-role client (bypasses RLS)
  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
  );

  try {
    const body = await req.json();
    const { action } = body;

    switch (action) {
      case "dequeue": {
        const { data, error } = await supabase.rpc("dequeue_scan_job");
        if (error) return json({ error: error.message }, 500);
        return json(data ?? []);
      }

      case "complete": {
        const { p_job_id, p_scan_id, p_score, p_duration_ms, p_page_title, p_findings, p_metadata } = body;
        const { error } = await supabase.rpc("complete_scan_job", {
          p_job_id,
          p_scan_id,
          p_score,
          p_duration_ms,
          p_page_title: p_page_title ?? "",
          p_findings: p_findings ?? [],
          p_metadata: p_metadata ?? {},
        });
        if (error) return json({ error: error.message }, 500);
        return json({ ok: true });
      }

      case "fail": {
        const { p_job_id, p_scan_id, p_error } = body;
        const { data, error } = await supabase.rpc("fail_scan_job", {
          p_job_id,
          p_scan_id,
          p_error,
        });
        if (error) return json({ error: error.message }, 500);
        return json({ willRetry: data });
      }

      case "heartbeat": {
        const { p_scanner_id, p_pool_size, p_active } = body;
        const { error } = await supabase.rpc("scanner_heartbeat", {
          p_scanner_id,
          p_pool_size,
          p_active,
        });
        if (error) return json({ error: error.message }, 500);
        return json({ ok: true });
      }

      case "get_session_cookies": {
        const { p_session_id } = body;
        const { data, error } = await supabase.rpc("get_session_cookies", {
          p_session_id,
        });
        if (error) return json({ error: error.message }, 500);
        return json(data ?? []);
      }

      default:
        return json({ error: `Unknown action: ${action}` }, 400);
    }
  } catch (err) {
    return json({ error: err.message ?? "Internal error" }, 500);
  }
});
