<?php
/**
 * Test page to debug mitigation API
 * Shows actual API response when accessed from authenticated session
 */

header('Content-Type: text/html; charset=UTF-8');

// Simulate API call
ob_start();
include __DIR__ . '/mitigation_data.php';
$apiResponse = ob_get_clean();

?>
<!DOCTYPE html>
<html>
<head>
    <title>Mitigation API Test</title>
    <style>
        body { font-family: monospace; padding: 20px; background: #0a0e14; color: #00ff88; }
        pre { background: #1a1e24; padding: 15px; border-radius: 5px; overflow-x: auto; }
        h1 { color: #00ffff; }
        .status { color: #ffaa00; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Mitigation API Debug Test</h1>

    <div class="status">API Response:</div>
    <pre><?php echo htmlspecialchars($apiResponse); ?></pre>

    <div class="status">Formatted JSON:</div>
    <pre><?php
        $data = json_decode($apiResponse, true);
        echo htmlspecialchars(json_encode($data, JSON_PRETTY_PRINT));
    ?></pre>

    <div class="status">Summary:</div>
    <pre><?php
        if ($data && isset($data['summary'])) {
            echo "Total Issues: " . ($data['summary']['total_issues'] ?? 0) . "\n";
            echo "Critical: " . ($data['summary']['critical'] ?? 0) . "\n";
            echo "High: " . ($data['summary']['high'] ?? 0) . "\n";
            echo "Medium: " . ($data['summary']['medium'] ?? 0) . "\n";
            echo "Projects: " . count($data['projects'] ?? []) . "\n";
        } else {
            echo "ERROR: Invalid response\n";
        }
    ?></pre>

    <div class="status">JavaScript Test:</div>
    <script>
        // Test what JavaScript sees
        fetch('mitigation_data.php')
            .then(res => res.json())
            .then(data => {
                console.log('JavaScript fetch result:', data);
                document.getElementById('js-result').textContent = JSON.stringify(data, null, 2);
            })
            .catch(err => {
                console.error('JavaScript fetch error:', err);
                document.getElementById('js-result').textContent = 'ERROR: ' + err.message;
            });
    </script>
    <pre id="js-result">Loading...</pre>
</body>
</html>
