<?php
// Backend quản lý bài tập — PHP 7.4+ và SQLite (thư viện có sẵn ở hầu hết hosting PHP)
const MIME=['jpg'=>'image/jpeg','jpeg'=>'image/jpeg','png'=>'image/png','gif'=>'image/gif','webp'=>'image/webp','pdf'=>'application/pdf','doc'=>'application/msword','docx'=>'application/vnd.openxmlformats-officedocument.wordprocessingml.document','xls'=>'application/vnd.ms-excel','xlsx'=>'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','ppt'=>'application/vnd.ms-powerpoint','pptx'=>'application/vnd.openxmlformats-officedocument.presentationml.presentation','txt'=>'text/plain'];
$D=__DIR__.'/data';$UP="$D/up";$SS="$D/sess";
foreach([$D,$UP,$SS] as $d)if(!is_dir($d))mkdir($d,0755,true);
if(!file_exists("$D/.htaccess"))file_put_contents("$D/.htaccess","<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
if(!file_exists("$D/index.html"))file_put_contents("$D/index.html",'');
function out($x,$c=200){http_response_code($c);header('Content-Type: application/json; charset=utf-8');echo json_encode($x,JSON_UNESCAPED_UNICODE);exit;}
function err($m,$c=400){out(['error'=>$m],$c);}
set_exception_handler(function($e){error_log($e);err('Lỗi máy chủ',500);});
function tx($v,$n=200){$v=trim((string)$v);return function_exists('mb_substr')?mb_substr($v,0,$n):substr($v,0,$n);}
$g=glob("$D/db_*.sqlite");$dbf=$g?$g[0]:"$D/db_".bin2hex(random_bytes(12)).'.sqlite';
$pdo=new PDO('sqlite:'.$dbf);$pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);$pdo->exec('PRAGMA foreign_keys=ON');
$pdo->exec("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,username TEXT NOT NULL UNIQUE COLLATE NOCASE,hash TEXT NOT NULL,role TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS classes(id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE,grade TEXT,subject TEXT);
CREATE TABLE IF NOT EXISTS enroll(user_id INT REFERENCES users(id) ON DELETE CASCADE,class_id INT REFERENCES classes(id) ON DELETE CASCADE,PRIMARY KEY(user_id,class_id));
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY,title TEXT NOT NULL,descr TEXT,class_id INT REFERENCES classes(id) ON DELETE CASCADE,due TEXT,maxscore REAL);
CREATE TABLE IF NOT EXISTS task_to(task_id INT REFERENCES tasks(id) ON DELETE CASCADE,user_id INT REFERENCES users(id) ON DELETE CASCADE,PRIMARY KEY(task_id,user_id));
CREATE TABLE IF NOT EXISTS subs(id INTEGER PRIMARY KEY,task_id INT REFERENCES tasks(id) ON DELETE CASCADE,user_id INT REFERENCES users(id) ON DELETE CASCADE,note TEXT,at TEXT,score REAL,fb TEXT,UNIQUE(task_id,user_id));
CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY,sub_id INT REFERENCES subs(id) ON DELETE CASCADE,name TEXT,mime TEXT,path TEXT);");
function q($s,$p=[]){global $pdo;$st=$pdo->prepare($s);$st->execute($p);return $st;}
function unl($cond,$p){global $UP;foreach(q("SELECT f.path FROM files f JOIN subs s ON s.id=f.sub_id WHERE $cond",$p)->fetchAll(PDO::FETCH_COLUMN) as $x)@unlink("$UP/$x");}
function ids($r){$r['id']=(string)$r['id'];return $r;}
function me($u){return ['id'=>(string)$u['id'],'name'=>$u['name'],'role'=>$u['role'],'cl'=>array_map('strval',q('SELECT class_id FROM enroll WHERE user_id=?',[$u['id']])->fetchAll(PDO::FETCH_COLUMN))];}
function login_as($id){session_regenerate_id(true);$_SESSION['uid']=$id;}
session_save_path($SS);session_set_cookie_params(['httponly'=>true,'samesite'=>'Lax','secure'=>!empty($_SERVER['HTTPS'])]);session_start();

$a=$_GET['a']??'';$post=$_SERVER['REQUEST_METHOD']==='POST';
if($post&&($_SERVER['HTTP_X_REQ']??'')!=='1')err('Yêu cầu không hợp lệ',403);
$in=$_POST;if($post&&stripos($_SERVER['CONTENT_TYPE']??'','json')!==false)$in=json_decode(file_get_contents('php://input'),true)?:[];
$u=null;if(!empty($_SESSION['uid']))$u=q('SELECT id,name,role FROM users WHERE id=?',[$_SESSION['uid']])->fetch(PDO::FETCH_ASSOC)?:null;
$nu=(int)q('SELECT COUNT(*) FROM users')->fetchColumn();

if($a==='me')out(['setup'=>$nu===0,'user'=>$u?me($u):null]);
if($a==='setup'){if($nu)err('Đã thiết lập rồi',403);$n=tx($in['name']??'',80);$un=tx($in['username']??'',30);$pw=(string)($in['password']??'');
 if($n===''||!preg_match('/^[A-Za-z0-9._-]{3,30}$/',$un))err('Nhập họ tên; tên đăng nhập 3–30 ký tự (chữ không dấu, số, . _ -)');if(strlen($pw)<6)err('Mật khẩu từ 6 ký tự');
 q("INSERT INTO users(name,username,hash,role) VALUES(?,?,?,'t')",[$n,$un,password_hash($pw,PASSWORD_DEFAULT)]);login_as((int)$pdo->lastInsertId());out(['user'=>me(['id'=>$_SESSION['uid'],'name'=>$n,'role'=>'t'])]);}
if($a==='login'){$r=q('SELECT id,name,role,hash FROM users WHERE username=?',[tx($in['username']??'',30)])->fetch(PDO::FETCH_ASSOC);
 if(!$r||!password_verify((string)($in['password']??''),$r['hash'])){usleep(500000);err('Sai tên đăng nhập hoặc mật khẩu',401);}login_as((int)$r['id']);out(['user'=>me($r)]);}
if($a==='logout'){$_SESSION=[];session_destroy();out(['ok'=>1]);}
if(!$u)err('Chưa đăng nhập',401);
$T=$u['role']==='t';

if($a==='pass'){$r=q('SELECT hash FROM users WHERE id=?',[$u['id']])->fetch(PDO::FETCH_ASSOC);if(!password_verify((string)($in['old']??''),$r['hash']))err('Mật khẩu hiện tại chưa đúng');
 if(strlen((string)($in['new']??''))<6)err('Mật khẩu mới từ 6 ký tự');q('UPDATE users SET hash=? WHERE id=?',[password_hash($in['new'],PASSWORD_DEFAULT),$u['id']]);out(['ok'=>1]);}

if($a==='data'){
 $cls=$T?q('SELECT id,name,grade,subject FROM classes ORDER BY grade,subject,name')->fetchAll(PDO::FETCH_ASSOC):q('SELECT c.id,c.name,c.grade,c.subject FROM classes c JOIN enroll e ON e.class_id=c.id WHERE e.user_id=? ORDER BY c.grade,c.subject,c.name',[$u['id']])->fetchAll(PDO::FETCH_ASSOC);
 $users=[];if($T){$en=[];foreach(q('SELECT user_id,class_id FROM enroll')->fetchAll(PDO::FETCH_NUM) as $r)$en[$r[0]][]=(string)$r[1];
  foreach(q("SELECT id,name,username FROM users WHERE role='s' ORDER BY name")->fetchAll(PDO::FETCH_ASSOC) as $r)$users[]=['id'=>(string)$r['id'],'name'=>$r['name'],'user'=>$r['username'],'cl'=>$en[$r['id']]??[]];}
 $to=[];foreach(q('SELECT task_id,user_id FROM task_to')->fetchAll(PDO::FETCH_NUM) as $r)$to[$r[0]][]=(string)$r[1];
 $tw=$T?'':'WHERE id IN (SELECT task_id FROM task_to WHERE user_id='.(int)$u['id'].')';$tasks=[];
 foreach(q("SELECT id,title,descr,class_id,due,maxscore FROM tasks $tw ORDER BY id")->fetchAll(PDO::FETCH_ASSOC) as $r)$tasks[]=['id'=>(string)$r['id'],'title'=>$r['title'],'desc'=>(string)$r['descr'],'cls'=>(string)$r['class_id'],'due'=>(string)$r['due'],'max'=>(float)$r['maxscore'],'to'=>$T?($to[$r['id']]??[]):[]];
 $fl=[];foreach(q('SELECT id,sub_id,name,mime FROM files')->fetchAll(PDO::FETCH_ASSOC) as $r)$fl[$r['sub_id']][]=['id'=>(string)$r['id'],'n'=>$r['name'],'t'=>$r['mime']];
 $sw=$T?'':'WHERE user_id='.(int)$u['id'];$subs=[];
 foreach(q("SELECT id,task_id,user_id,note,at,score,fb FROM subs $sw")->fetchAll(PDO::FETCH_ASSOC) as $r)$subs[]=['id'=>(string)$r['id'],'task'=>(string)$r['task_id'],'student'=>(string)$r['user_id'],'note'=>(string)$r['note'],'at'=>$r['at'],'score'=>$r['score']===null?null:(float)$r['score'],'fb'=>(string)$r['fb'],'files'=>$fl[$r['id']]??[]];
 out(['classes'=>array_map('ids',$cls),'users'=>$users,'tasks'=>$tasks,'subs'=>$subs]);}

if($a==='file'){$f=q('SELECT f.name,f.mime,f.path,s.user_id FROM files f JOIN subs s ON s.id=f.sub_id WHERE f.id=?',[(int)($_GET['id']??0)])->fetch(PDO::FETCH_ASSOC);
 if(!$f||(!$T&&(int)$f['user_id']!==(int)$u['id']))err('Không có quyền',403);$p="$UP/".$f['path'];if(!is_file($p))err('Không tìm thấy file',404);session_write_close();
 header('Content-Type: '.$f['mime']);header('X-Content-Type-Options: nosniff');header('Content-Length: '.filesize($p));header('Cache-Control: private, max-age=3600');
 header('Content-Disposition: '.(strpos($f['mime'],'image/')===0?'inline':'attachment')."; filename*=UTF-8''".rawurlencode($f['name']));readfile($p);exit;}

if($a==='submit'){
 if($T)err('Chỉ học sinh mới nộp bài',403);$tid=(int)($in['task']??0);
 if(!q('SELECT 1 FROM task_to WHERE task_id=? AND user_id=?',[$tid,$u['id']])->fetch())err('Bài này không giao cho bạn',403);
 if(q('SELECT 1 FROM subs WHERE task_id=? AND user_id=? AND score IS NOT NULL',[$tid,$u['id']])->fetch())err('Bài đã được chấm, không nộp lại được');
 if(!$_POST&&!$_FILES&&(int)($_SERVER['CONTENT_LENGTH']??0)>0)err('Dữ liệu gửi lên quá lớn so với giới hạn của máy chủ');
 $note=tx($in['note']??'',2000);$fs=[];$F=$_FILES['f']??null;
 if($F){foreach((array)$F['name'] as $i=>$nm){if($F['error'][$i]===UPLOAD_ERR_NO_FILE)continue;$nm=basename($nm);
  if($F['error'][$i]!==UPLOAD_ERR_OK)err('Không tải được "'.$nm.'" (có thể vượt giới hạn của máy chủ)');
  $ex=strtolower(pathinfo($nm,PATHINFO_EXTENSION));if(!isset(MIME[$ex]))err('Không hỗ trợ loại file: '.$nm);if($F['size'][$i]>10*1048576)err('File quá lớn (tối đa 10MB): '.$nm);$fs[]=[$nm,$ex,$F['tmp_name'][$i]];}}
 if(count($fs)>10)err('Tối đa 10 file');if(!$fs&&$note==='')err('Hãy chọn file hoặc nhập ghi chú');
 unl('s.user_id=? AND s.task_id=?',[$u['id'],$tid]);q('DELETE FROM subs WHERE user_id=? AND task_id=?',[$u['id'],$tid]);
 q('INSERT INTO subs(task_id,user_id,note,at) VALUES(?,?,?,?)',[$tid,$u['id'],$note,gmdate('Y-m-d\TH:i:s\Z')]);$sid=$pdo->lastInsertId();
 foreach($fs as $x){$p=bin2hex(random_bytes(16));if(move_uploaded_file($x[2],"$UP/$p"))q('INSERT INTO files(sub_id,name,mime,path) VALUES(?,?,?,?)',[$sid,tx($x[0],150),MIME[$x[1]],$p]);}
 out(['ok'=>1]);}

if(!$T)err('Chỉ giáo viên',403);
$id=(int)($in['id']??0);
switch($a){
case 'addClass':$gr=tx($in['grade']??'',10);$m=tx($in['subject']??'',30);$l=tx($in['label']??'',40);if($gr===''||$m==='')err('Chọn khối và môn');
 try{q('INSERT INTO classes(name,grade,subject) VALUES(?,?,?)',[$m.' '.$gr.($l!==''?' – '.$l:''),$gr,$m]);}catch(PDOException $e){err('Lớp này đã tồn tại');}out(['ok'=>1]);
case 'delClass':unl('s.task_id IN (SELECT id FROM tasks WHERE class_id=?)',[$id]);q('DELETE FROM classes WHERE id=?',[$id]);out(['ok'=>1]);
case 'addStu':$n=tx($in['name']??'',80);$un=tx($in['username']??'',30);$pw=(string)($in['password']??'');$cl=array_filter(array_map('intval',(array)($in['classes']??[])));
 if($n===''||!preg_match('/^[A-Za-z0-9._-]{3,30}$/',$un))err('Nhập họ tên; tên đăng nhập 3–30 ký tự (chữ không dấu, số, . _ -)');if(strlen($pw)<6)err('Mật khẩu từ 6 ký tự');if(!$cl)err('Chọn ít nhất 1 lớp');
 try{q("INSERT INTO users(name,username,hash,role) VALUES(?,?,?,'s')",[$n,$un,password_hash($pw,PASSWORD_DEFAULT)]);}catch(PDOException $e){err('Tên đăng nhập đã tồn tại');}
 $nid=$pdo->lastInsertId();foreach($cl as $c)q('INSERT OR IGNORE INTO enroll VALUES(?,?)',[$nid,$c]);out(['ok'=>1]);
case 'setPw':if(strlen((string)($in['password']??''))<6)err('Mật khẩu từ 6 ký tự');q("UPDATE users SET hash=? WHERE id=? AND role='s'",[password_hash($in['password'],PASSWORD_DEFAULT),$id]);out(['ok'=>1]);
case 'delStu':unl('s.user_id=?',[$id]);q("DELETE FROM users WHERE id=? AND role='s'",[$id]);out(['ok'=>1]);
case 'addTo':q('INSERT OR IGNORE INTO enroll VALUES(?,?)',[$id,(int)($in['class']??0)]);out(['ok'=>1]);
case 'leave':$c=(int)($in['class']??0);$sub='SELECT id FROM tasks WHERE class_id=?';unl("s.user_id=? AND s.task_id IN ($sub)",[$id,$c]);
 q("DELETE FROM subs WHERE user_id=? AND task_id IN ($sub)",[$id,$c]);q("DELETE FROM task_to WHERE user_id=? AND task_id IN ($sub)",[$id,$c]);q('DELETE FROM enroll WHERE user_id=? AND class_id=?',[$id,$c]);out(['ok'=>1]);
case 'addTask':$t=tx($in['title']??'',200);$c=(int)($in['cls']??0);if($t==='')err('Nhập tiêu đề');
 $ok=q('SELECT user_id FROM enroll WHERE class_id=?',[$c])->fetchAll(PDO::FETCH_COLUMN);$to=array_values(array_intersect(array_map('intval',(array)($in['to']??[])),array_map('intval',$ok)));if(!$to)err('Chọn ít nhất 1 học sinh trong lớp');
 q('INSERT INTO tasks(title,descr,class_id,due,maxscore) VALUES(?,?,?,?,?)',[$t,tx($in['desc']??'',5000),$c,tx($in['due']??'',10),(float)($in['max']??10)?:10]);$tid=$pdo->lastInsertId();
 foreach($to as $s)q('INSERT INTO task_to VALUES(?,?)',[$tid,$s]);out(['ok'=>1]);
case 'delTask':unl('s.task_id=?',[$id]);q('DELETE FROM tasks WHERE id=?',[$id]);out(['ok'=>1]);
case 'grade':$s=q('SELECT s.id,t.maxscore FROM subs s JOIN tasks t ON t.id=s.task_id WHERE s.id=?',[(int)($in['sub']??0)])->fetch(PDO::FETCH_ASSOC);if(!$s)err('Không tìm thấy bài nộp',404);
 $sc=$in['score']??null;$sc=($sc===null||$sc==='')?null:max(0,min((float)$sc,(float)$s['maxscore']));q('UPDATE subs SET score=?,fb=? WHERE id=?',[$sc,tx($in['fb']??'',2000),$s['id']]);out(['ok'=>1]);
}
err('Không rõ yêu cầu',404);
