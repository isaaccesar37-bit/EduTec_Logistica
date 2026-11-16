import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const publishableKeys = Deno.env.get("SUPABASE_PUBLISHABLE_KEYS");
const secretKeys = Deno.env.get("SUPABASE_SECRET_KEYS");
const anonKey = publishableKeys ? JSON.parse(publishableKeys).default : Deno.env.get("SUPABASE_ANON_KEY")!;
const serviceRoleKey = secretKeys ? JSON.parse(secretKeys).default : Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

function corsHeaders(request: Request) {
  const allowedOrigin = Deno.env.get("APP_ORIGIN");
  const requestOrigin = request.headers.get("Origin") ?? "*";
  return {
    "Access-Control-Allow-Origin": allowedOrigin ?? "*",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin"
  };
}

Deno.serve(async (request) => {
  const headers = corsHeaders(request);
  if (request.method === "OPTIONS") return new Response("ok", { headers });
  if (request.method !== "POST") {
    return Response.json({ error: "Método não permitido." }, { status: 405, headers });
  }

  try {
    const { username, password } = await request.json();
    const normalizedUsername = String(username ?? "").trim().toLowerCase();
    if (normalizedUsername.length < 3 || normalizedUsername.length > 40 || typeof password !== "string" || password.length === 0) {
      return Response.json({ error: "Usuário ou senha inválidos." }, { status: 401, headers });
    }

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false }
    });
    const { data: account, error: accountError } = await admin
      .from("user_accounts")
      .select("user_id")
      .eq("username", normalizedUsername)
      .maybeSingle();
    if (accountError || !account) {
      return Response.json({ error: "Usuário ou senha inválidos." }, { status: 401, headers });
    }

    const { data: userResult, error: userError } = await admin.auth.admin.getUserById(account.user_id);
    const email = userResult.user?.email;
    if (userError || !email) {
      return Response.json({ error: "Usuário ou senha inválidos." }, { status: 401, headers });
    }

    const publicClient = createClient(supabaseUrl, anonKey, {
      auth: { persistSession: false, autoRefreshToken: false }
    });
    const { data: authResult, error: authError } = await publicClient.auth.signInWithPassword({ email, password });
    if (authError || !authResult.session) {
      return Response.json({ error: "Usuário ou senha inválidos." }, { status: 401, headers });
    }

    return Response.json({
      session: {
        access_token: authResult.session.access_token,
        refresh_token: authResult.session.refresh_token
      }
    }, { status: 200, headers });
  } catch (_error) {
    return Response.json({ error: "Não foi possível concluir o login." }, { status: 400, headers });
  }
});
