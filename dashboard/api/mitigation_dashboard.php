<?php
/**
 * Mitigation Dashboard - Full View
 * Renders the complete mitigation dashboard in HTML
 */

$base_dir = dirname(dirname(__DIR__));
$dashboard_file = "$base_dir/MITIGATION_DASHBOARD.md";

if (!file_exists($dashboard_file)) {
    http_response_code(404);
    echo "Dashboard not found. Run the scanner to generate it.";
    exit;
}

$markdown = file_get_contents($dashboard_file);
$markdown_json = json_encode($markdown);

?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Mitigation Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0e27;
            color: #e0e6ed;
            padding: 2rem;
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: #141938;
            border-radius: 8px;
            padding: 2rem;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        }

        h1 {
            color: #00d4ff;
            border-bottom: 2px solid #00d4ff;
            padding-bottom: 0.5rem;
            margin-bottom: 1.5rem;
        }

        h2 {
            color: #00d4ff;
            margin-top: 2rem;
            margin-bottom: 1rem;
        }

        h3 {
            color: #4a9eff;
            margin-top: 1.5rem;
            margin-bottom: 0.75rem;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            background: #1a1f3a;
            border-radius: 4px;
            overflow: hidden;
        }

        th {
            background: #1e2442;
            color: #00d4ff;
            padding: 0.75rem;
            text-align: left;
            font-weight: 600;
        }

        td {
            padding: 0.75rem;
            border-bottom: 1px solid #2a2f4a;
        }

        tr:hover {
            background: #1e2442;
        }

        code {
            background: #0a0e27;
            color: #00ff88;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }

        pre {
            background: #0a0e27;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            margin: 1rem 0;
        }

        pre code {
            background: none;
            padding: 0;
        }

        a {
            color: #4a9eff;
            text-decoration: none;
        }

        a:hover {
            color: #00d4ff;
            text-decoration: underline;
        }

        hr {
            border: none;
            border-top: 1px solid #2a2f4a;
            margin: 2rem 0;
        }

        .refresh-note {
            text-align: right;
            color: #7a8ba3;
            font-size: 0.9rem;
            margin-bottom: 1rem;
        }

        strong {
            color: #00ff88;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="refresh-note">
            <a href="javascript:location.reload()">Refresh</a> |
            <a href="../">Back to Dashboard</a>
        </div>
        <div id="content"></div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <script>
        var markdownContent = <?php echo $markdown_json; ?>;
        document.getElementById('content').innerHTML = marked.parse(markdownContent);
    </script>
</body>
</html>
