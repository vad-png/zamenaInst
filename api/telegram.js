const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).end();
  try {
    const { hash, ...rest } = req.body || {};
    const check = Object.keys(rest).sort().map(k => `${k}=${rest[k]}`).join('\n');
    const secret = crypto.createHash('sha256').update(process.env.TELEGRAM_BOT_TOKEN).digest();
    const calc = crypto.createHmac('sha256', secret).update(check).digest('hex');
    if (!hash || calc !== hash) return res.status(401).json({ error: 'bad signature' });
    if (Date.now() / 1000 - Number(rest.auth_date) > 86400) return res.status(401).json({ error: 'expired' });

    const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
    const email = `tg_${rest.id}@telegram.local`;
    const name = [rest.first_name, rest.last_name].filter(Boolean).join(' ') || rest.username || 'Без имени';
    await sb.auth.admin.createUser({ email, email_confirm: true, user_metadata: { name, tg_id: rest.id } }); // "already exists" is fine
    const { data, error } = await sb.auth.admin.generateLink({ type: 'magiclink', email });
    if (error) throw error;
    res.json({ token_hash: data.properties.hashed_token });
  } catch (e) {
    res.status(500).json({ error: 'server' });
  }
};
