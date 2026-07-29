export default {
  async fetch(request, env) {
    // 1. Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
        },
      });
    }

    const headers = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    };

    try {
      // Parse request body safely
      const body = await request.json().catch(() => ({}));
      const { action, org_id, post_id, member_id, query, full_name, bio, contact } = body;

      // Validate JWT session token from header
      const authHeader = request.headers.get('Authorization') || '';
      const token = authHeader.replace('Bearer ', '').trim();

      if (!token) {
        return new Response(JSON.stringify({ success: false, message: 'Unauthorized request.' }), { status: 401, headers });
      }

      // Initialize Supabase Admin / Service Role client inside Worker
      const supabase = createSupabaseClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, token);

      // Verify user identity
      const { data: { user }, error: authErr } = await supabase.auth.getUser();
      if (authErr || !user) {
        return new Response(JSON.stringify({ success: false, message: 'Invalid or expired session.' }), { status: 401, headers });
      }

      // ── Action: Delete (Unlink) Post ──
      if (action === 'delete_post') {
        if (!org_id || !post_id) {
          return new Response(JSON.stringify({ success: false, message: 'Missing org_id or post_id.' }), { status: 400, headers });
        }

        // Verify requester is org owner OR has admin role
        const canManage = await checkOrgAdminPermission(supabase, user.id, org_id);
        if (!canManage) {
          return new Response(JSON.stringify({ success: false, message: 'You do not have permission to delete posts in this organization.' }), { status: 403, headers });
        }

        // Set org_id = null instead of deleting the row
        const { error: updateErr } = await supabase
          .from('posts')
          .update({ org_id: null })
          .eq('id', post_id)
          .eq('org_id', org_id);

        if (updateErr) throw updateErr;

        return new Response(JSON.stringify({ success: true, message: 'Post unlinked from organization.' }), { status: 200, headers });
      }

      // ── Action: Remove Member ──
      if (action === 'remove_member') {
        if (!org_id || !member_id) {
          return new Response(JSON.stringify({ success: false, message: 'Missing org_id or member_id.' }), { status: 400, headers });
        }

        const canManage = await checkOrgAdminPermission(supabase, user.id, org_id);
        if (!canManage) {
          return new Response(JSON.stringify({ success: false, message: 'You do not have permission to remove members.' }), { status: 403, headers });
        }

        const { error: removeErr } = await supabase
          .from('organizations')
          .delete()
          .eq('org_id', org_id)
          .eq('member_id', member_id);

        if (removeErr) throw removeErr;

        return new Response(JSON.stringify({ success: true, message: 'Member removed from organization.' }), { status: 200, headers });
      }

      // Default fallback for unknown action
      return new Response(JSON.stringify({ success: false, message: 'Invalid action.' }), { status: 400, headers });

    } catch (err) {
      // Mask rate limit, gateway, or unexpected errors with a clean response
      const errString = String(err?.message || err).toLowerCase();
      const isRateLimit = errString.includes('rate') || errString.includes('limit') || errString.includes('429') || errString.includes('exceeded');

      const userFriendlyMessage = isRateLimit || err?.status === 429
        ? "We're experiencing high traffic or temporary limit issues. Please wait a moment and try again."
        : "We're experiencing temporary technical issues processing your request. Please try again shortly.";

      return new Response(
    JSON.stringify({ 
      success: false, 
      message: err.message || String(err),
      stack: err.stack 
    }),
    { status: 500, headers }
  );
    }
  }
};

// Helper function to check if user is the Org account itself OR an 'admin' member
async function checkOrgAdminPermission(supabase, userId, orgId) {
  // Check if exact org
  if (userId === orgId) return true;

  // Check member role in database
  const { data: member } = await supabase
    .from('organizations')
    .select('member_role')
    .eq('org_id', orgId)
    .eq('member_id', userId)
    .maybeSingle();

  return member?.member_role === 'admin';
}
