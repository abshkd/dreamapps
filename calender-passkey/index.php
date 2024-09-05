<?php
require_once __DIR__ . '/vendor/autoload.php';

use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptionsFactory;
use Webauthn\PublicKeyCredentialRequestOptionsFactory;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialLoader;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA;
use Cose\Algorithm\Signature\EdDSA;
use Cose\Algorithm\Signature\RSA;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\TokenBinding\IgnoreTokenBindingHandler;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;

session_start();

class CredentialRepository implements PublicKeyCredentialSourceRepository
{
    private SQLite3 $db;

    public function __construct(SQLite3 $db)
    {
        $this->db = $db;
    }

    public function findOneByCredentialId(string $credentialId): ?PublicKeyCredentialSource
    {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE credential_id = :credential_id');
        $stmt->bindValue(':credential_id', $credentialId, SQLITE3_TEXT);
        $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

        if (!$result) {
            return null;
        }

        return new PublicKeyCredentialSource(
            credentialId: $result['credential_id'],
            type: 'public-key',
            transports: json_decode($result['transports'], true),
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: $result['aaguid'],
            credentialPublicKey: base64_decode($result['public_key']),
            counter: (int)$result['counter'],
            userHandle: $result['user_handle']
        );
    }

    public function findAllForUserEntity(PublicKeyCredentialUserEntity $userEntity): array
    {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE username = :username');
        $stmt->bindValue(':username', $userEntity->getName(), SQLITE3_TEXT);
        $result = $stmt->execute();

        $credentialSources = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $credentialSources[] = new PublicKeyCredentialSource(
                credentialId: $row['credential_id'],
                type: 'public-key',
                transports: json_decode($row['transports'], true),
                attestationType: 'none',
                trustPath: new EmptyTrustPath(),
                aaguid: $row['aaguid'],
                credentialPublicKey: base64_decode($row['public_key']),
                counter: (int)$row['counter'],
                userHandle: $row['username']
            );
        }

        return $credentialSources;
    }

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        $stmt = $this->db->prepare('INSERT INTO users (username, credential_id, public_key, calendar_url) VALUES (:username, :credential_id, :public_key, :calendar_url)');
        $stmt->bindValue(':username', $publicKeyCredentialSource->getUserHandle(), SQLITE3_TEXT);
        $stmt->bindValue(':credential_id', $publicKeyCredentialSource->getPublicKeyCredentialId(), SQLITE3_TEXT);
        $stmt->bindValue(':public_key', base64_encode(serialize($publicKeyCredentialSource->getPublicKey())), SQLITE3_TEXT);
        $stmt->bindValue(':calendar_url', $this->generate_calendar_url(), SQLITE3_TEXT);
        $stmt->execute();
    }

    private function generate_calendar_url(): string
    {
        return bin2hex(random_bytes(8));
    }
}

// Initialize SQLite and create tables if they don't exist
$db = new SQLite3('calendar.db');
$db->exec('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, credential_id TEXT, public_key TEXT, calendar_url TEXT)');
$db->exec('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, start_time DATETIME, end_time DATETIME)');

$rpEntity = new PublicKeyCredentialRpEntity(
    'Calendar App',
    'calendar.airith.com',
    null
);

$credentialRepository = new CredentialRepository($db);

$attestationStatementSupportManager = new AttestationStatementSupportManager();
$authenticatorAttestationResponseValidator = new AuthenticatorAttestationResponseValidator(
    $attestationStatementSupportManager,
    $credentialRepository
);

$extensionOutputCheckerHandler = new ExtensionOutputCheckerHandler(); // Instantiate ExtensionOutputCheckerHandler

$authenticatorAssertionResponseValidator = new AuthenticatorAssertionResponseValidator(
    $credentialRepository,
    new IgnoreTokenBindingHandler(),  // Correct TokenBindingHandler
    $extensionOutputCheckerHandler,   // Correct ExtensionOutputCheckerHandler
    new Manager([
        new ECDSA\ES256(),
        new ECDSA\ES384(),
        new ECDSA\ES512(),
        new EdDSA\Ed25519(),
        new RSA\RS256(),
    ])
);

$creationOptionsFactory = new PublicKeyCredentialCreationOptionsFactory(
    $rpEntity,
    $credentialRepository,
    $attestationStatementSupportManager
);

$requestOptionsFactory = new PublicKeyCredentialRequestOptionsFactory(
    $credentialRepository
);


// Handle AJAX requests
if (isset($_GET['action'])) {
    header('Content-Type: application/json');

    try {
        switch ($_GET['action']) {
            case 'register_options':
                $username = $_POST['username'] ?? '';
                $userEntity = new PublicKeyCredentialUserEntity(
                    $username,
                    bin2hex(random_bytes(16)),
                    $username,
                    null
                );

                $authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria(
                    AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
                    false,
                    AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED
                );

                $publicKeyCredentialCreationOptions = $creationOptionsFactory->create(
                    $userEntity,
                    PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
                    $authenticatorSelectionCriteria
                );


                $_SESSION['publicKeyCredentialCreationOptions'] = $publicKeyCredentialCreationOptions;

                echo json_encode($publicKeyCredentialCreationOptions);
                break;

            case 'register':
                $data = json_decode(file_get_contents('php://input'), true);
                $publicKeyCredentialCreationOptions = $_SESSION['publicKeyCredentialCreationOptions'];
                $publicKeyCredential = $server->loadAndCheckPublicKeyCredential($data['credential']);
                $credentialSource = $server->getAuthenticatorAttestationResponseValidator()->check(
                    $publicKeyCredential->getResponse(),
                    $publicKeyCredentialCreationOptions,
                    null
                );

                $credentialRepository->saveCredentialSource($credentialSource);
                echo json_encode(['success' => true]);
                break;

            case 'login_options':
                $username = $_POST['username'] ?? '';
                $user = $credentialRepository->findOneByCredentialId($username);
                if ($user) {
                    $publicKeyCredentialRequestOptions = $requestOptionsFactory->create(
                        PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED
                    );


                    $_SESSION['publicKeyCredentialRequestOptions'] = $publicKeyCredentialRequestOptions;
                    $_SESSION['login_username'] = $username;

                    echo json_encode([
                        'success' => true,
                        'options' => $publicKeyCredentialRequestOptions,
                        'calendar_url' => $user['calendar_url']
                    ]);
                } else {
                    echo json_encode(['success' => false]);
                }
                break;

            case 'verify_login':
                $data = json_decode(file_get_contents('php://input'), true);
                $publicKeyCredentialRequestOptions = $_SESSION['publicKeyCredentialRequestOptions'];
                $username = $_SESSION['login_username'];
                $user = $credentialRepository->findOneByCredentialId($username);

                $publicKeyCredential = $server->loadAndCheckPublicKeyCredential($data['credential']);
                $server->getAuthenticatorAssertionResponseValidator()->check(
                    $publicKeyCredential->getResponse(),
                    $publicKeyCredentialRequestOptions,
                    null,
                    null,
                    $user['credential_id'],
                    unserialize(base64_decode($user['public_key']))
                );

                $_SESSION['user_id'] = $user['id'];
                $_SESSION['calendar_url'] = $user['calendar_url'];

                echo json_encode(['success' => true, 'calendar_url' => $user['calendar_url']]);
                break;

            case 'add_event':
                if (isset($_SESSION['user_id'])) {
                    $title = $_POST['title'];
                    $start_time = $_POST['start_time'];
                    $end_time = $_POST['end_time'];
                    add_event($_SESSION['user_id'], $title, $start_time, $end_time);
                    echo json_encode(['success' => true]);
                } else {
                    echo json_encode(['success' => false]);
                }
                break;

            case 'get_events':
                if (isset($_SESSION['user_id'])) {
                    $events = get_events($_SESSION['user_id']);
                    echo json_encode($events);
                } else {
                    echo json_encode([]);
                }
                break;
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
    exit;
}

function add_event($user_id, $title, $start_time, $end_time)
{
    global $db;
    $stmt = $db->prepare('INSERT INTO events (user_id, title, start_time, end_time) VALUES (:user_id, :title, :start_time, :end_time)');
    $stmt->bindValue(':user_id', $user_id, SQLITE3_INTEGER);
    $stmt->bindValue(':title', $title, SQLITE3_TEXT);
    $stmt->bindValue(':start_time', $start_time, SQLITE3_TEXT);
    $stmt->bindValue(':end_time', $end_time, SQLITE3_TEXT);
    $stmt->execute();
}

function get_events($user_id)
{
    global $db;
    $stmt = $db->prepare('SELECT * FROM events WHERE user_id = :user_id ORDER BY start_time');
    $stmt->bindValue(':user_id', $user_id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $events = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $events[] = $row;
    }
    return $events;
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Calendar App</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/fullcalendar/3.10.2/fullcalendar.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.29.1/moment.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/fullcalendar/3.10.2/fullcalendar.min.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }

        #calendar {
            max-width: 900px;
            margin: 0 auto;
        }

        .form-container {
            max-width: 300px;
            margin: 20px auto;
        }

        input,
        button {
            display: block;
            width: 100%;
            margin-bottom: 10px;
            padding: 5px;
        }

        #notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 10px;
            background-color: #f0f0f0;
            border: 1px solid #ccc;
            border-radius: 5px;
            display: none;
        }
    </style>
</head>

<body>
    <div id="app">
        <div id="auth-forms" class="form-container">
            <h2>Register</h2>
            <form id="register-form">
                <input type="text" id="register-username" name="username" placeholder="Username" autocomplete="username webauthn">
                <button type="submit">Register</button>
            </form>

            <h2>Login</h2>
            <form id="login-form">
                <input type="text" id="login-username" name="username" placeholder="Username" autocomplete="username webauthn">
                <button type="submit">Login</button>
            </form>
        </div>

        <div id="calendar-container" style="display: none;">
            <h2>Your Calendar</h2>
            <p>Your calendar URL: <span id="calendar-url"></span></p>
            <div id="calendar"></div>
        </div>
    </div>

    <div id="notification"></div>

    <script>
        $(document).ready(function() {
            let calendar;

            function showNotification(message) {
                $('#notification').text(message).fadeIn().delay(3000).fadeOut();
            }

            function initializeCalendar() {
                calendar = $('#calendar').fullCalendar({
                    header: {
                        left: 'prev,next today',
                        center: 'title',
                        right: 'month,agendaWeek,agendaDay'
                    },
                    selectable: true,
                    selectHelper: true,
                    select: function(start, end) {
                        var title = prompt('Event Title:');
                        if (title) {
                            var eventData = {
                                title: title,
                                start: start.format(),
                                end: end.format()
                            };
                            $.post('index.php?action=add_event', eventData, function(response) {
                                if (response.success) {
                                    calendar.fullCalendar('renderEvent', eventData, true);
                                    showNotification('Event added successfully');
                                } else {
                                    showNotification('Failed to add event');
                                }
                            }, 'json');
                        }
                        calendar.fullCalendar('unselect');
                    },
                    editable: true,
                    eventLimit: true
                });

                // Load events
                $.get('index.php?action=get_events', function(events) {
                    calendar.fullCalendar('addEventSource', events);
                });
            }

            async function registerUser(username) {
                try {
                    const response = await fetch('index.php?action=register_options', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `username=${encodeURIComponent(username)}`,
                    });
                    const publicKeyCredentialCreationOptions = await response.json();

                    publicKeyCredentialCreationOptions.challenge = Uint8Array.from(
                        atob(publicKeyCredentialCreationOptions.challenge), c => c.charCodeAt(0)
                    );
                    publicKeyCredentialCreationOptions.user.id = Uint8Array.from(
                        atob(publicKeyCredentialCreationOptions.user.id), c => c.charCodeAt(0)
                    );

                    const credential = await navigator.credentials.create({
                        publicKey: publicKeyCredentialCreationOptions
                    });

                    const credentialResponse = await fetch('index.php?action=register', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            username: username,
                            credential: {
                                id: credential.id,
                                rawId: btoa(String.fromCharCode.apply(null, new Uint8Array(credential.rawId))),
                                type: credential.type,
                                response: {
                                    attestationObject: btoa(String.fromCharCode.apply(null, new Uint8Array(credential.response.attestationObject))),
                                    clientDataJSON: btoa(String.fromCharCode.apply(null, new Uint8Array(credential.response.clientDataJSON))),
                                },
                            },
                        }),
                    });

                    const result = await credentialResponse.json();
                    if (result.success) {
                        showNotification('Registration successful. You can now log in.');
                    } else {
                        showNotification('Registration failed. Please try again.');
                    }
                } catch (error) {
                    showNotification('Registration failed: ' + error.message);
                }
            }

            async function loginUser(username) {
                try {
                    const response = await fetch('index.php?action=login_options', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `username=${encodeURIComponent(username)}`,
                    });

                    const data = await response.json();

                    if (!data.success) {
                        showNotification('User not found. Please register first.');
                        return;
                    }

                    const publicKeyCredentialRequestOptions = data.options;
                    publicKeyCredentialRequestOptions.challenge = Uint8Array.from(
                        atob(publicKeyCredentialRequestOptions.challenge), c => c.charCodeAt(0)
                    );
                    publicKeyCredentialRequestOptions.allowCredentials = publicKeyCredentialRequestOptions.allowCredentials.map(credential => ({
                        ...credential,
                        id: Uint8Array.from(atob(credential.id), c => c.charCodeAt(0)),
                    }));

                    const assertion = await navigator.credentials.get({
                        publicKey: publicKeyCredentialRequestOptions
                    });

                    const verificationResponse = await fetch('index.php?action=verify_login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            credential: {
                                id: assertion.id,
                                rawId: btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.rawId))),
                                type: assertion.type,
                                response: {
                                    authenticatorData: btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.response.authenticatorData))),
                                    clientDataJSON: btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.response.clientDataJSON))),
                                    signature: btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.response.signature))),
                                    userHandle: assertion.response.userHandle ? btoa(String.fromCharCode.apply(null, new Uint8Array(assertion.response.userHandle))) : null,
                                },
                            },
                        }),
                    });

                    const verificationResult = await verificationResponse.json();

                    if (verificationResult.success) {
                        $('#auth-forms').hide();
                        $('#calendar-container').show();
                        $('#calendar-url').text(window.location.origin + '/calendar/' + data.calendar_url);
                        initializeCalendar();
                        showNotification('Login successful');
                    } else {
                        showNotification('Login failed. Please try again.');
                    }
                } catch (error) {
                    showNotification('Login failed: ' + error.message);
                }
            }

            $('#register-form').submit(function(e) {
                e.preventDefault();
                var username = $('#register-username').val();
                registerUser(username);
            });

            $('#login-form').submit(function(e) {
                e.preventDefault();
                var username = $('#login-username').val();
                loginUser(username);
            });
        });
    </script>
</body>

</html>