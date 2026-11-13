import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) return json({ error: "Unauthorized" }, 401);

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !anonKey || !serviceRoleKey) {
      return json({ error: "Server secrets are not configured" }, 500);
    }

    const token = authHeader.slice("Bearer ".length);
    const userClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: `Bearer ${token}` } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: userData, error: userError } = await userClient.auth.getUser();
    if (userError || !userData.user) return json({ error: "Invalid session" }, 401);

    const adminClient = createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: adminRow, error: adminCheckError } = await adminClient
      .from("admin_users")
      .select("user_id")
      .eq("user_id", userData.user.id)
      .maybeSingle();
    if (adminCheckError || !adminRow) return json({ error: "Admin access required" }, 403);

    const body = await req.json().catch(() => ({}));
    const targetId = typeof body.user_id === "string" ? body.user_id : "";
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(targetId)) {
      return json({ error: "Invalid student user ID" }, 400);
    }
    if (targetId === userData.user.id) return json({ error: "You cannot delete your own admin account here" }, 400);

    const { data: targetAdmin, error: targetAdminError } = await adminClient
      .from("admin_users")
      .select("user_id")
      .eq("user_id", targetId)
      .maybeSingle();
    if (targetAdminError) return json({ error: "Could not verify target account" }, 500);
    if (targetAdmin) return json({ error: "Admin accounts cannot be deleted from the student list" }, 403);

    const { error: deleteAuthError } = await adminClient.auth.admin.deleteUser(targetId);
    if (deleteAuthError) return json({ error: deleteAuthError.message }, 400);

    // Clean up explicitly in case the students table does not cascade on auth user deletion.
    const { error: deleteProfileError } = await adminClient
      .from("students")
      .delete()
      .eq("user_id", targetId);
    if (deleteProfileError) return json({ error: "Auth account deleted, but profile cleanup failed: " + deleteProfileError.message }, 500);

    return json({ success: true });
  } catch (error) {
    return json({ error: error instanceof Error ? error.message : "Unexpected server error" }, 500);
  }
});