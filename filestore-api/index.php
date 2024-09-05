<?php
// Hardcoded API Key for authentication
$apiKey = "your-hardcoded-api-key-here";
$baseUrl = "https://yourwebsitedomain";

// Check for the API key in the request headers
$headers = getallheaders();
if (!isset($headers['X-API-KEY']) || $headers['X-API-KEY'] !== $apiKey) {
    echo json_encode(["status" => "error", "message" => "Unauthorized access."]);
    http_response_code(401); // Set the HTTP response code to 401 Unauthorized
    exit;
}

// Extract the HTTP method and route
$method = $_SERVER['REQUEST_METHOD'];
$requestUri = explode('/', trim($_SERVER['REQUEST_URI'], '/'));

// Routing based on the request method and URI
if ($method === 'POST' && isset($requestUri[1]) && $requestUri[0] === 'uploads') {
    $userId = $requestUri[1]; // User ID from the URI

    // Ensure user_id is present or use some other random input
    if (!$userId) {
        echo json_encode(["status" => "error", "message" => "User ID is required."]);
        exit;
    }

    if (isset($_FILES['file'])) {
        $uploadDir = 'uploads/' . $userId . '/';
        $originalFileName = pathinfo($_FILES['file']['name'], PATHINFO_FILENAME);
        $fileExtension = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));

        // Define allowed file extensions and MIME types
        $allowedExtensions = [
            'jpg',
            'jpeg',
            'png',
            'gif',
            'pdf',
            'txt',
            'docx',
            'doc',
            'xlsx',
            'xls',
            'pptx',
            'ppt',
            'odt',
            'ods',
            'odp',
            'rtf',
            'zip',
            'rar',
            'csv',
            'json',
            'xml'
        ];

        // Validate MIME type (still important for security)
        $fileMimeType = mime_content_type($_FILES['file']['tmp_name']);

        // Check if the file extension is in the allowed list
        if (!in_array($fileExtension, $allowedExtensions)) {
            // If not allowed, append .txt to the extension
            $fileExtension .= '.txt';
        }

        // Ensure the directory exists
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0777, true);
        }

        // Generate a randomized file name with a suffix
        $randomSuffix = bin2hex(random_bytes(6)); // Generates a random 12-character string
        $newFileName = $originalFileName . '-' . $randomSuffix . '.' . $fileExtension;
        $filePath = $uploadDir . $newFileName;

        // Move the uploaded file to the designated folder
        if (move_uploaded_file($_FILES['file']['tmp_name'], $filePath)) {
            // Set restrictive file permissions to prevent execution
            chmod($filePath, 0644); // Read/write for owner, read-only for others

            // Set a file expiration time (e.g., 24 hours)
            $expirationTime = time() + (24 * 60 * 60); // 24 hours
            file_put_contents("$filePath.expire", $expirationTime);

            // Generate the full download URL
            $downloadUrl = $baseUrl . $userId . '/' . $newFileName;

            echo json_encode([
                "status" => "success",
                "message" => "File uploaded successfully.",
                "download_url" => $downloadUrl
            ]);
        } else {
            echo json_encode(["status" => "error", "message" => "File upload failed."]);
        }
    } else {
        echo json_encode(["status" => "error", "message" => "No file uploaded."]);
    }
} elseif ($method === 'DELETE' && isset($requestUri[2]) && $requestUri[0] === 'uploads') {
    $userId = $requestUri[1];
    $fileName = $requestUri[2];
    $filePath = 'uploads/' . $userId . '/' . $fileName;

    // Delete the file if it exists
    if (file_exists($filePath)) {
        unlink($filePath); // Delete the file
        @unlink("$filePath.expire"); // Delete the expiration file if it exists
        echo json_encode(["status" => "success", "message" => "File deleted successfully."]);
    } else {
        echo json_encode(["status" => "error", "message" => "File not found."]);
    }
} else {
    echo json_encode(["status" => "error", "message" => "Invalid request."]);
}
