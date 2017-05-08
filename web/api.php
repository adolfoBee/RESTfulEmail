<?php

session_cache_limiter(false);

require_once '../vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;

// create a log channel
$log = new Logger('main');
$log->pushHandler(new StreamHandler('../everything.log', Logger::DEBUG));
$log->pushHandler(new StreamHandler('../errors.log', Logger::ERROR));

// http://meekro.com/
//$url = parse_url(getenv("us-cdbr-iron-east-03.cleardb.net/heroku_ec730381fb7f"));

DB::$host = 'us-cdbr-iron-east-03.cleardb.net';
DB::$dbName = 'heroku_ec730381fb7fa69';
DB::$user = 'bd2b17519b40d8';
DB::$password = '116d23b3';
DB::$port = 3306;

DB::$error_handler = 'sql_error_handler';
DB::$nonsql_error_handler = 'nonsql_error_handler';

function nonsql_error_handler($params) {
    global $app, $log;
    $log->error(" Database error: " . $params['error']);
    http_response_code(500);
    echo '"500 - Internal error"';
    die;
}

function sql_error_handler($params) {
    global $app, $log;
    $log->error(" SQL error: " . $params['error']);
    $log->error(" in query: " . $params['query']);
    http_response_code(500);
    echo '"500 - Internal error"';
    die;
}

// https://docs.slimframework.com/
$app = new \Slim\Slim();

// http://docs.slimframework.com/routing/conditions/
\Slim\Route::setDefaultConditions(array(
    'id' => '\d+'
));

$app->response->headers->set('content-type', 'application/json');

//-------------------------------------------FUNCTIONS-------------------------------------------------------------------------------

function isUserValid($user, &$error) {
    $row = DB::queryFirstRow("SELECT * FROM users WHERE email=%s", $user['email']);
    if ($row) {
        $error = "Email already registered.";
        return false;
    }
    if (strlen($user['fullName']) > 50 || strlen($user['fullName']) < 2) {
        $error = "Full name length must between 2 and 50 characters.";
        return false;
    }
    if (filter_var($user['email'], FILTER_VALIDATE_EMAIL) === FALSE) {
        $error = "Email looks invalid.";
        return false;
    }
    if (strlen($user['password']) < 8 || strlen($user['password']) > 100) {
        $error = "Password must be 8 to 100 characters long.";
        return false;
    }
    $regex = "/^(?=.*[a-z])(?=.*[A-Z])(?=.*[\d$@$!%*?&]).*$/";
    if (preg_match($regex, $user['password']) !== 1) {
        $error = "Password must contain 1 upper case, 1 lower case and 1 number or special character.";
        return false;
    }
    return true;
}

function getAuthUserId() {
    global $app, $log;
    $email = $app->request->headers("PHP_AUTH_USER");
    $password = $app->request->headers("PHP_AUTH_PW");
    if ($email && $password) {
        $row = DB::queryFirstRow("SELECT * FROM users WHERE email=%s", $email);
        if ($row && $row['password'] == $password) {
            return $row['ID'];
        }
    }
    $log->debug("BASIC authentication failed for user " . $email . " from " . $_SERVER['REMOTE_ADDR']);
    $app->response()->status(401);
    return false;
}

function isFolderValid($folder, &$error) {
    if ($folder == "Inbox" || $folder == "Important" || $folder == "Social" || $folder == "Spam" || $folder == "Outbox") {
        return true;
    }
    $error = "Folder invalid.";
    return false;
}

function isNewEmailValid($subject, $to, &$error) {
    if (strlen($subject) > 200 || strlen($subject) < 2) {
        $error = "Subject length must between 2 and 200 characters.";
        return false;
    }
    $regex = "/ /";
    if (filter_var($to, FILTER_VALIDATE_EMAIL) === FALSE || preg_match($regex, $to) === 1) {
        $error = "Email looks invalid.";
        return false;
    }
    return true;
}

function isPasswordValid($user, &$error) {
    if (strlen($user['fullName']) > 50 || strlen($user['fullName']) < 2) {
        $error = "Full name length must between 2 and 50 characters.";
        return false;
    }
    if (strlen($user['npw']) < 8 || strlen($user['npw']) > 100) {
        $error = "Password must be 8 to 100 characters long.";
        return false;
    }
    $regex = "/^(?=.*[a-z])(?=.*[A-Z])(?=.*[\d$@$!%*?&]).*$/";
    if (preg_match($regex, $user['npw']) !== 1) {
        $error = "Password must contain 1 upper case, 1 lower case and 1 number or special character.";
        return false;
    }
    return true;
}

//-------------------------------------------MAIN------------------------------------------------------------------------------------

$app->get('/', function() use($app) {
    $app->response->headers->set('content-type', 'text/html');
    echo file_get_contents('register.html');
});

//-------------------------------------------USER------------------------------------------------------------------------------------

$app->get('/api/users/:email', function($email) use($app, $log) {
    $userID = getAuthUserId();
    if (!getAuthUserId()) {
        return;
    }
    $user = DB::queryFirstRow('SELECT ID, email, fullName FROM users WHERE email=%s', $email);
    if (!$user) {
        $app->response()->setStatus(404);
        $log->debug("GET /users/" . $user . "returned 404");
        echo json_encode("404 - user not found");
        return;
    }
    if ($user['ID'] != $userID){ 
        $app->response()->setStatus(403);
        $log->debug("GET /users/" . $user . "returned 403");
        echo json_encode("403 - forbidden");
        return;
    }
    echo json_encode($user, JSON_PRETTY_PRINT);
});

$app->post('/api/users', function() use ($app, $log) {

    $body = $app->request->getBody();
    $user = json_decode($body, TRUE);
    if (!isUserValid($user, $error)) {
        $app->response()->setStatus(400);
        $log->debug("POST /users [[" . $user . "]] data invalid: " . $error);
        echo json_encode("400 - data invalid: " . $error);
        return;
    }
    DB::insert('users', $user);
    echo json_encode("");
    $app->response->setStatus(201);
});

$app->put('/api/users/:email', function($email = "") use($app, $log) {
    $userID = getAuthUserId();
    if (!getAuthUserId()) {
        return;
    }
    $body = $app->request->getBody();
    $user = json_decode($body, TRUE);

    if (!isPasswordValid($user, $error)) {
        $app->response()->setStatus(400);
        $log->debug("PUT /users/password [[" . $user['email'] . "]] data invalid: " . $error);
        echo json_encode("400 - data invalid: " . $error);
        return;
    }
    $id=DB::queryOneField("ID", "SELECT ID FROM users WHERE email=%s", $user['email']);
    if ($id != $userID){ 
        $app->response()->setStatus(403);
        $log->debug("PUT /users/password" . $user['email'] . "returned 403");
        echo json_encode("403 - forbidden");
        return;
    }
    DB::update('users', array('password' => $user['npw'], 'fullName' => $user['fullName']), "ID=%i", $userID);
    echo json_encode(true);
});

//-------------------------------------------EMAILS----------------------------------------------------------------------------------



$app->get('/api/emails/folder/:folder', function($folder = "Inbox") use($app, $log) {
    $userID = getAuthUserId();
    if (!getAuthUserId()) {
        return;
    }
    $emails = DB::query('SELECT ID, userID, efrom, eto, subject, body, dateSent FROM emails WHERE userID=%i AND folder=%s', $userID, $folder);
    if (!$emails) {
        $app->response()->setStatus(404);
        $log->debug("GET /emails/" . $folder . "returned 404");
        echo json_encode("404 - user not found");
        return;
    }
    if ($emails[0]['userID'] != $userID){ 
        $app->response()->setStatus(403);
        $log->debug("GET /emails/" . $folder . "returned 403");
        echo json_encode("403 - forbidden");
        return;
    }
    echo json_encode($emails, JSON_PRETTY_PRINT);
});

$app->get('/api/emails/:id', function($emailID = 0) use($app, $log) {
    $userID = getAuthUserId();
    if (!getAuthUserId()) {
        return;
    }
    $email = DB::queryFirstRow('SELECT ID, userID, efrom, eto, subject, body, dateSent, folder, attachmentMimeType FROM emails WHERE ID=%i AND userID=%i', $emailID, $userID);
    if (!$email) {
        $app->response()->setStatus(404);
        $log->debug("GET /emails/" . $emailID . "returned 404");
        echo json_encode("404 - user not found");
        return;
    }
    if ($email['userID'] != $userID){ 
        $app->response()->setStatus(403);
        $log->debug("GET /emails/" . $emailID . "returned 403");
        echo json_encode("403 - forbidden");
        return;
    }
    echo json_encode($email, JSON_PRETTY_PRINT);
});

$app->get('/api/emails/:id/attachment', function($emailID = 0) {
    $email = DB::queryFirstRow('SELECT attachment, attachmentMimeType, attachmentFileName FROM emails WHERE ID=%i', $emailID);

    header("Content-length: " . strlen($email['attachment']));
    header("Content-Type: " . $email['attachmentMimeType']);
    header("Content-Disposition: attachment; filename={$email['attachmentFileName']}");
    echo $email['attachment'];
});

$app->put('/api/emails/:id', function($emailID = 0) use($app, $log) {
    $userID = getAuthUserId();
    if (!getAuthUserId()) {
        return;
    }
    $body = $app->request->getBody();
    $folder = json_decode($body, TRUE);

    if (!isFolderValid($folder, $error)) {
        $app->response()->setStatus(400);
        $log->debug("PUT /emails/ [[" . $emailID . "]] data invalid: " . $error);
        echo json_encode("400 - data invalid: " . $error);
        return;
    }
    $userID2=DB::queryOneField("userID", "SELECT userID FROM emails WHERE ID=%s", $emailID);
    if ($userID2 != $userID){ 
        $app->response()->setStatus(403);
        $log->debug("PUT /emails/" . $emailID . "returned 403");
        echo json_encode("403 - forbidden");
        return;
    }
    DB::update('emails', array('folder' => $folder), "ID=%i AND userID=%i", $emailID, $userID);
    echo json_encode(true);
});

$app->post('/api/emails', function() use($app, $log) {
    $userID = getAuthUserId();
    if (!getAuthUserId()) {
        return;
    }
    $email = $app->request->headers("PHP_AUTH_USER");
    $today = date("Y-m-d");

    $to = $_POST['to'];
    $subject = $_POST['subject'];
    $body = $_POST['body'];

    if (!isNewEmailValid($subject, $to, $error)) {
        $app->response()->setStatus(400);
        $log->debug("POST /emails [[" . $to . "]], ". $subject .", ". $body ." data invalid: " . $error);
        echo json_encode("400 - data invalid: " . $error);
        return;
    }
        
    if (isset($_POST['file'])) {
        $attachment = $_POST['file'];
        list($type, $attachment) = explode(';', $attachment);
        list(, $attachment)      = explode(',', $attachment);
        $blob = base64_decode($attachment);
        //$blob = $data = base64_decode(preg_replace('#^data:image/\w+;base64,#i', '', $attachment));
        
        $attachmentMimeType = $_POST['attachmentMimeType'];
        $attachmentFileName = $_POST['attachmentFileName'];
        DB::insert('emails', array(
            'userID' => $userID,
            'folder' => 'Outbox',
            'dateSent' => $today,
            'efrom' => $email,
            'eto' => $to,
            'subject' => $subject,
            'body' => $body,
            'attachment' => $blob,
            'attachmentMimeType' => $attachmentMimeType,
            'attachmentFileName' => $attachmentFileName
        ));
    } else {
        DB::insert('emails', array(
            'userID' => $userID,
            'folder' => 'Outbox',
            'dateSent' => $today,
            'efrom' => $email,
            'eto' => $to,
            'subject' => $subject,
            'body' => $body
        ));
    }
    echo json_encode(true);
});

//SEND EMAILS
$app->get('/api/queue', function() use ($app, $log) {
    $app->response()['Content-Type'] = 'application/json';
    $deliveredCount = 0;
    $undeliveredEmails = array();
    $emailList = DB::query("SELECT ID, eto FROM emails WHERE folder='Outbox'");
    foreach ($emailList as $email) {
        $recipientID = DB::queryOneField("ID","SELECT * FROM users WHERE email=%s", $email['eto']);
        if ($recipientID) { // recipient found
            DB::update('emails', array('userID' => $recipientID, 'folder' => 'Inbox'), 'ID=%i', $email['ID']);
            $deliveredCount++;
        } else { // recipient not found
            array_push($undeliveredEmails, $email['eto']);
        }
    }
    $retval = array(
        "processed" => count($emailList),
        "delivered" => $deliveredCount,
        "undeliveredList" => $undeliveredEmails
    );
    echo json_encode($retval, JSON_PRETTY_PRINT);
});

$app->run();
