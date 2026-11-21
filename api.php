<?php
// No database needed. Accounts are saved in game_data.php next to this file.
// Just upload this file and index.html to the same folder (htdocs).
$OWNER_NAME = 'rafaelgwapo';   // this username becomes the owner. Sign up with it FIRST.

header('Content-Type: application/json'); header('Cache-Control: no-store');
$FILE = __DIR__ . '/game_data.php';
$GUARD = "<?php http_response_code(403); exit; ?>\n";   // stops anyone reading the file in a browser

$fp = @fopen($FILE, 'c+');
if (!$fp) { echo json_encode(['ok'=>0,'err'=>'db']); exit; }
flock($fp, LOCK_EX);
$raw = stream_get_contents($fp);
$db = $raw ? json_decode(substr($raw, strlen($GUARD)), true) : null;
if (!is_array($db)) $db = ['users'=>[], 'sessions'=>[], 'next'=>1];

function done($a, $save = false) {
  global $fp, $db, $GUARD;
  if ($save) { ftruncate($fp, 0); rewind($fp); fwrite($fp, $GUARD . json_encode($db)); fflush($fp); }
  flock($fp, LOCK_UN); fclose($fp);
  echo json_encode($a); exit;
}
function uout($u) { return ['name'=>$u['name'], 'role'=>$u['role'], 'data'=>$u['data'] ?: new stdClass()]; }
function newtok($uid) {
  global $db; $t = bin2hex(random_bytes(32)); $db['sessions'][$t] = ['uid'=>$uid, 'at'=>time()];
  if (count($db['sessions']) > 5000) $db['sessions'] = array_slice($db['sessions'], -2500, null, true);
  return $t;
}

$in = json_decode(file_get_contents('php://input'), true) ?: [];
$a = $in['a'] ?? ''; $tok = (string)($in['t'] ?? '');

if ($a === 'signup') {
  $n = trim($in['name'] ?? ''); $p = (string)($in['pass'] ?? '');
  if (!preg_match('/^[A-Za-z0-9_-]{2,12}$/', $n)) done(['ok'=>0,'err'=>'Name: 2-12 letters, numbers, - or _']);
  if (strlen($p) < 4 || strlen($p) > 72) done(['ok'=>0,'err'=>'Password needs 4 or more characters']);
  foreach ($db['users'] as $u) if ($u['low'] === strtolower($n)) done(['ok'=>0,'err'=>'used']);
  $id = $db['next']++;
  $role = strtolower($n) === strtolower($OWNER_NAME) ? 'owner' : 'member';
  $data = is_array($in['data'] ?? null) ? $in['data'] : [];
  $db['users'][$id] = ['id'=>$id, 'name'=>$n, 'low'=>strtolower($n), 'pass'=>password_hash($p, PASSWORD_DEFAULT), 'role'=>$role, 'banned'=>0, 'data'=>$data];
  $t = newtok($id);
  done(['ok'=>1, 'token'=>$t, 'name'=>$n, 'role'=>$role, 'data'=>$data ?: new stdClass()], true);
}
if ($a === 'login') {
  $f = null; $low = strtolower(trim($in['name'] ?? ''));
  foreach ($db['users'] as $u) if ($u['low'] === $low) $f = $u;
  if (!$f || !password_verify((string)($in['pass'] ?? ''), $f['pass'])) done(['ok'=>0,'err'=>'bad']);
  if ($f['banned']) done(['ok'=>0,'err'=>'banned']);
  // enforce roles on every login: only $OWNER_NAME is owner, everyone else is member
  $want = $f['low'] === strtolower($OWNER_NAME) ? 'owner' : 'member';
  if ($f['role'] !== $want) { $f['role'] = $want; $db['users'][$f['id']]['role'] = $want; }
  $t = newtok($f['id']);
  done(['ok'=>1, 'token'=>$t] + uout($f), true);
}

$s = $db['sessions'][$tok] ?? null;
if ($s && time() - $s['at'] > 60*60*24*30) $s = null;
$u = $s ? ($db['users'][$s['uid']] ?? null) : null;
if (!$u) done(['ok'=>0,'err'=>'auth']);
if ($u['banned']) done(['ok'=>0,'err'=>'banned']);

if ($a === 'me') done(['ok'=>1] + uout($u));
if ($a === 'logout') { unset($db['sessions'][$tok]); done(['ok'=>1], true); }
if ($a === 'save') {
  $d = $in['data'] ?? null;
  if (!is_array($d) || strlen(json_encode($d)) > 200000) done(['ok'=>0,'err'=>'bad data']);
  $db['users'][$u['id']]['data'] = $d; done(['ok'=>1], true);
}
if ($a === 'list' || $a === 'ban' || $a === 'setrole') {
  if ($u['role'] !== 'owner' && !($u['role'] === 'admin' && $a !== 'setrole')) done(['ok'=>0,'err'=>'forbidden']);
  if ($a === 'list') {
    $r = []; foreach ($db['users'] as $x) $r[] = ['id'=>$x['id'], 'name'=>$x['name'], 'role'=>$x['role'], 'banned'=>(int)$x['banned']];
    done(['ok'=>1, 'users'=>$r]);
  }
  $tid = (int)($in['id'] ?? 0); $t = $db['users'][$tid] ?? null;
  if (!$t || $t['role'] === 'owner' || $tid === $u['id']) done(['ok'=>0,'err'=>'invalid target']);
  if ($u['role'] === 'admin' && $t['role'] !== 'member') done(['ok'=>0,'err'=>'forbidden']);
  if ($a === 'setrole') { $db['users'][$tid]['role'] = (($in['role'] ?? '') === 'admin') ? 'admin' : 'member'; done(['ok'=>1], true); }
  $b = !empty($in['ban']) ? 1 : 0; $db['users'][$tid]['banned'] = $b;
  if ($b) foreach ($db['sessions'] as $k => $ss) if ($ss['uid'] === $tid) unset($db['sessions'][$k]);
  done(['ok'=>1], true);
}
done(['ok'=>0,'err'=>'unknown']);
