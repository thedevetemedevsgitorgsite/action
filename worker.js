import { createClient } from '@supabase/supabase-js';

// Helper to initialize Supabase with user JWT
function getSupabaseClient(env, userToken) {
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error('Supabase environment variables are missing.');
  }

  return createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
    global: {
      headers: {
        Authorization: userToken ? `Bearer ${userToken}` : '',
      },
    },
  });
}

// Helper to check if requester is org owner or an 'admin' member
async function checkOrgAdminPermission(supabase, userId, orgId) {
  if (userId === orgId) return true;

  const { data: member } = await supabase
    .from('organizations')
    .select('member_role')
    .eq('org_id', orgId)
    .eq('member_id', userId)
    .maybeSingle();

  return member?.member_role === 'admin';
}

export default {
  async fetch(request, env) {
    const headers = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    };

    // 1. Preflight CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        },
      });
    }

    try {
      // 2. Validate Authorization Header
      const authHeader = request.headers.get('Authorization') || '';
      const token = authHeader.replace('Bearer ', '').trim();

      if (!token) {
        return new Response(
          JSON.stringify({ success: false, message: 'Unauthorized request.' }),
          { status: 401, headers }
        );
      }

      const supabase = getSupabaseClient(env, token);

      // Verify token authenticity
      const { data: { user }, error: authErr } = await supabase.auth.getUser(token);
      if (authErr || !user) {
        return new Response(
          JSON.stringify({ success: false, message: 'Invalid or expired session.' }),
          { status: 401, headers }
        );
      }

      const body = await request.json().catch(() => ({}));
      const { action, org_id, post_id, member_id, query, full_name, bio, contact } = body;

      // ── Action: Soft Delete / Unlink Post ──
      if (action === 'delete_post') {
        const canManage = await checkOrgAdminPermission(supabase, user.id, org_id);
        if (!canManage) {
          return new Response(
            JSON.stringify({ success: false, message: 'Permission denied.' }),
            { status: 403, headers }
          );
        }

        // Set org_id = null instead of deleting post record
        const { error } = await supabase
          .from('posts')
          .update({ org_id: null })
          .eq('id', post_id)
          .eq('org_id', org_id);

        if (error) throw error;
        return new Response(JSON.stringify({ success: true, message: 'Post unlinked from organization.' }), { status: 200, headers });
      }

      // ── Action: Remove Member ──
      if (action === 'remove_member') {
        const canManage = await checkOrgAdminPermission(supabase, user.id, org_id);
        if (!canManage) {
          return new Response(
            JSON.stringify({ success: false, message: 'Permission denied.' }),
            { status: 403, headers }
          );
        }

        const { error } = await supabase
          .from('organizations')
          .delete()
          .eq('org_id', org_id)
          .eq('member_id', member_id);

        if (error) throw error;
        return new Response(JSON.stringify({ success: true, message: 'Member removed.' }), { status: 200, headers });
      }

      // ── Action: Leave Organization ──
      if (action === 'leave_organization') {
        const { error } = await supabase
          .from('organizations')
          .delete()
          .eq('org_id', org_id)
          .eq('member_id', user.id);

        if (error) throw error;
        return new Response(JSON.stringify({ success: true, message: 'Left organization.' }), { status: 200, headers });
      }

      // ── Action: Add Member ──
      if (action === 'add_member') {
        const canManage = await checkOrgAdminPermission(supabase, user.id, org_id);
        if (!canManage) {
          return new Response(JSON.stringify({ success: false, message: 'Permission denied.' }), { status: 403, headers });
        }

        const { data: targetUser } = await supabase
          .from('profiles')
          .select('id')
          .or(`username.eq.${query},email.eq.${query}`)
          .maybeSingle();

        if (!targetUser) {
          return new Response(JSON.stringify({ success: false, message: 'User not found.' }), { status: 404, headers });
        }

        const { error } = await supabase
          .from('organizations')
          .insert({ org_id, member_id: targetUser.id, member_role: 'member' });

        if (error) throw error;
        return new Response(JSON.stringify({ success: true, message: 'Member added.' }), { status: 200, headers });
      }

      // ── Action: Update Profile ──
      if (action === 'update_profile') {
        const canManage = await checkOrgAdminPermission(supabase, user.id, org_id);
        if (!canManage) {
          return new Response(JSON.stringify({ success: false, message: 'Permission denied.' }), { status: 403, headers });
        }

        const { error } = await supabase
          .from('profiles')
          .update({ full_name, bio })
          .eq('id', org_id);

        if (error) throw error;
        return new Response(JSON.stringify({ success: true, message: 'Profile updated.' }), { status: 200, headers });
      }

      // ── Action: Update Contact ──
      if (action === 'update_contact') {
        const canManage = await checkOrgAdminPermission(supabase, user.id, org_id);
        if (!canManage) {
          return new Response(JSON.stringify({ success: false, message: 'Permission denied.' }), { status: 403, headers });
        }

        const { error } = await supabase
          .from('profiles')
          .update({ contact })
          .eq('id', org_id);

        if (error) throw error;
        return new Response(JSON.stringify({ success: true, message: 'Contact saved.' }), { status: 200, headers });
      }

      return new Response(JSON.stringify({ success: false, message: 'Invalid action.' }), { status: 400, headers });

    } catch (err) {
      console.error('Worker Execution Exception:', err);

      const errString = String(err?.message || err).toLowerCase();
      const isRateLimit = errString.includes('rate') || errString.includes('limit') || errString.includes('429');

      const userFriendlyMessage = isRateLimit
        ? "We're experiencing high traffic or temporary limit issues. Please wait a moment and try again."
        : "We're experiencing temporary technical issues processing your request. Please try again shortly.";

      return new Response(
        JSON.stringify({ success: false, message: userFriendlyMessage }),
        { status: 500, headers }
      );
    }
  }
};

