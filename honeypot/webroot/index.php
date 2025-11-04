<!DOCTYPE html>
<html>
<head>
    <title>Document Management System</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 50px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container { 
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        h1 { 
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 15px;
            margin-top: 0;
        }
        .subtitle {
            color: #7f8c8d;
            margin-top: -10px;
            margin-bottom: 30px;
        }
        .upload-form { 
            margin: 30px 0;
            padding: 25px;
            background: #ecf0f1;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        .upload-form h2 {
            margin-top: 0;
            color: #34495e;
        }
        input[type="file"] {
            margin: 15px 0;
            padding: 10px;
            border: 2px dashed #bdc3c7;
            border-radius: 4px;
            width: 100%;
            box-sizing: border-box;
            background: white;
        }
        button { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: transform 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .file-list { 
            margin-top: 40px;
        }
        .file-list h2 {
            color: #34495e;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
        }
        .file-item { 
            padding: 15px;
            margin: 10px 0;
            background: #f8f9fa;
            border-radius: 6px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-left: 3px solid #3498db;
            transition: background 0.2s;
        }
        .file-item:hover {
            background: #e8eef2;
        }
        .file-info {
            flex-grow: 1;
        }
        .file-name {
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 5px;
        }
        .file-meta {
            font-size: 12px;
            color: #7f8c8d;
        }
        .file-link {
            color: #3498db;
            text-decoration: none;
            padding: 8px 16px;
            border: 1px solid #3498db;
            border-radius: 4px;
            transition: all 0.2s;
        }
        .file-link:hover {
            background: #3498db;
            color: white;
        }
        .alert { 
            padding: 15px 20px;
            border-radius: 6px;
            margin: 15px 0;
            display: flex;
            align-items: center;
        }
        .success { 
            background: #d4edda;
            color: #155724;
            border-left: 4px solid #28a745;
        }
        .error { 
            background: #f8d7da;
            color: #721c24;
            border-left: 4px solid #dc3545;
        }
        .footer {
            margin-top: 50px;
            padding-top: 25px;
            border-top: 1px solid #ecf0f1;
            text-align: center;
            color: #95a5a6;
            font-size: 13px;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            background: #3498db;
            color: white;
            border-radius: 3px;
            font-size: 11px;
            font-weight: 600;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📁 Document Management System <span class="badge">v2.1.4</span></h1>
        <p class="subtitle">Internal file sharing portal - Upload and manage documents securely</p>
        
        <div class="upload-form">
            <h2>📤 Upload Document</h2>
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="file" required>
                <button type="submit">Upload File</button>
            </form>
            
            <?php
            // INTENTIONALLY VULNERABLE - No file type validation
            if(isset($_FILES['file'])) {
                $target_dir = "uploads/";
                $target_file = $target_dir . basename($_FILES["file"]["name"]);
                
                if (!file_exists($target_dir)) {
                    mkdir($target_dir, 0777, true);
                }
                
                // Log upload attempt
                $log_entry = json_encode([
                    'timestamp' => date('Y-m-d H:i:s'),
                    'filename' => $_FILES["file"]["name"],
                    'size' => $_FILES["file"]["size"],
                    'type' => $_FILES["file"]["type"],
                    'ip' => $_SERVER['REMOTE_ADDR'],
                    'user_agent' => $_SERVER['HTTP_USER_AGENT']
                ]) . "\n";
                file_put_contents('/var/log/honeypot/uploads.log', $log_entry, FILE_APPEND);
                
                if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
                    echo "<div class='alert success'>✓ File uploaded successfully: <strong>" . htmlspecialchars(basename($_FILES["file"]["name"])) . "</strong></div>";
                    echo "<p>Access your file: <a href='$target_file' style='color: #3498db; font-weight: 600;'>$target_file</a></p>";
                } else {
                    echo "<div class='alert error'>✗ Upload failed. Please try again.</div>";
                }
            }
            ?>
        </div>
        
        <div class="file-list">
            <h2>📂 Uploaded Files</h2>
            <?php
            $upload_dir = 'uploads/';
            if (is_dir($upload_dir)) {
                $files = array_diff(scandir($upload_dir), array('.', '..'));
                if (count($files) > 0) {
                    echo "<div style='font-size: 13px; color: #7f8c8d; margin-bottom: 15px;'>Total files: <strong>" . count($files) . "</strong></div>";
                    foreach($files as $file) {
                        $file_path = $upload_dir . $file;
                        $file_size = filesize($file_path);
                        $file_time = date("Y-m-d H:i:s", filemtime($file_path));
                        echo "<div class='file-item'>";
                        echo "<div class='file-info'>";
                        echo "<div class='file-name'>📄 " . htmlspecialchars($file) . "</div>";
                        echo "<div class='file-meta'>" . number_format($file_size) . " bytes • Uploaded: $file_time</div>";
                        echo "</div>";
                        echo "<a href='$file_path' class='file-link'>View</a>";
                        echo "</div>";
                    }
                } else {
                    echo "<p style='color: #7f8c8d; text-align: center; padding: 30px;'>No files uploaded yet. Be the first to upload!</p>";
                }
            }
            ?>
        </div>
        
        <div class='footer'>
            <p><strong>Document Management System</strong> v2.1.4</p>
            <p>© 2025 Internal IT Department • All Rights Reserved</p>
        </div>
    </div>
</body>
</html>
