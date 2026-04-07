import 'dotenv/config';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!);

async function main() {
  await supabase.auth.signInWithPassword({ email: 'jose.santos@viverdeia.ai', password: 'Via@2026' });

  const { data: scans } = await supabase.from('scans')
    .select('id, url, score')
    .eq('url', 'https://dados.viverdeia.ai')
    .order('created_at', { ascending: false })
    .limit(1);

  if (!scans || scans.length === 0) { console.log('No scan found'); return; }

  const scan = scans[0];
  console.log(`=== ${scan.url} | Score: ${scan.score} ===\n`);

  const { data: findings } = await supabase.from('findings')
    .select('severity, type, title, description, location, remediation')
    .eq('scan_id', scan.id)
    .order('severity');

  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const sorted = findings!.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));

  for (const f of sorted) {
    const icon = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : f.severity === 'MEDIUM' ? '🟡' : '🟢';
    console.log(`${icon} [${f.severity}] ${f.title}`);
    console.log(`   ${(f.description || '').substring(0, 150)}`);
    if (f.location) console.log(`   📍 ${f.location.substring(0, 100)}`);
    console.log('');
  }

  console.log(`Total: ${sorted.length} findings`);
  process.exit(0);
}

main();
