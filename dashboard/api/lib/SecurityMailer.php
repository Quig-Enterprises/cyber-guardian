<?php
/**
 * SecurityMailer - SMTP mailer for Security Dashboard notifications.
 * Reads SMTP host/port from /etc/artemis/mail.conf, uses Artemis Security credentials.
 * Follows the same STARTTLS pattern as EqmonMailer.
 */
class SecurityMailer
{
    private const MAIL_CONF = '/etc/artemis/mail.conf';
    private const TEMPLATE_DIR = '/var/www/html/eqmon/templates/email/';
    private const MAX_RETRIES = 3;
    private const RETRY_DELAY = 2;
    private const CONNECT_TIMEOUT = 10;

    // Artemis Security sender credentials
    private const FROM_ADDRESS = 'artemis@devteam.quigs.com';
    private const FROM_NAME = 'Artemis Security';
    private const SMTP_USER = 'artemis@devteam.quigs.com';
    private const SMTP_PASS = '},oRNbOraN,81';

    private static ?array $config = null;

    /**
     * Send a raw email.
     */
    public static function send(string $to, string $subject, string $body, bool $isHtml = true): bool
    {
        $config = self::loadConfig();
        $lastError = null;

        for ($attempt = 1; $attempt <= self::MAX_RETRIES; $attempt++) {
            try {
                $socket = self::smtpConnect($config);
                self::sendMessage($socket, $to, $subject, $body, $isHtml);
                fclose($socket);

                openlog('security-mailer', LOG_PID, LOG_MAIL);
                syslog(LOG_INFO, "Mail delivered to {$to} subject=\"{$subject}\" attempt={$attempt}");
                closelog();
                return true;
            } catch (Throwable $e) {
                $lastError = $e->getMessage();
                openlog('security-mailer', LOG_PID, LOG_MAIL);
                syslog(LOG_ERR, "Mail attempt {$attempt} failed to {$to}: {$lastError}");
                closelog();
                if (isset($socket) && is_resource($socket)) {
                    @fclose($socket);
                }
                if ($attempt < self::MAX_RETRIES) {
                    sleep(self::RETRY_DELAY);
                }
            }
        }

        openlog('security-mailer', LOG_PID, LOG_MAIL);
        syslog(LOG_ERR, "Mail permanently failed to {$to} after " . self::MAX_RETRIES . " attempts: {$lastError}");
        closelog();
        return false;
    }

    /**
     * Send an email using a named template with {{placeholder}} substitution.
     * $vars must include 'subject'.
     */
    public static function sendTemplate(string $to, string $templateName, array $vars): bool
    {
        if (empty($vars['subject'])) {
            throw new InvalidArgumentException("SecurityMailer::sendTemplate() requires 'subject' in \$vars.");
        }

        $path = self::TEMPLATE_DIR . $templateName . '.html';
        if (!is_file($path) || !is_readable($path)) {
            openlog('security-mailer', LOG_PID, LOG_MAIL);
            syslog(LOG_ERR, "Template not found: {$path}");
            closelog();
            return false;
        }

        $html = file_get_contents($path);
        if ($html === false) return false;

        foreach ($vars as $key => $value) {
            $html = str_replace('{{' . $key . '}}', (string) $value, $html);
        }

        return self::send($to, $vars['subject'], $html, true);
    }

    // Load SMTP host/port from mail.conf
    private static function loadConfig(): array
    {
        if (self::$config !== null) return self::$config;

        $ini = parse_ini_file(self::MAIL_CONF, true);
        if ($ini === false) {
            throw new RuntimeException("SecurityMailer: cannot read " . self::MAIL_CONF);
        }

        self::$config = [
            'host' => $ini['smtp']['host'] ?? 'localhost',
            'port' => (int) ($ini['smtp']['port'] ?? 587),
            'timeout' => (int) ($ini['security']['timeout'] ?? 30),
        ];
        return self::$config;
    }

    // SMTP connect with STARTTLS + AUTH LOGIN
    private static function smtpConnect(array $config)
    {
        $host = $config['host'];
        $port = $config['port'];
        $errno = 0;
        $errstr = '';

        $socket = stream_socket_client(
            "tcp://{$host}:{$port}", $errno, $errstr, self::CONNECT_TIMEOUT
        );
        if ($socket === false) {
            throw new RuntimeException("SecurityMailer: connect failed to {$host}:{$port} - [{$errno}] {$errstr}");
        }

        stream_set_timeout($socket, self::CONNECT_TIMEOUT);

        // Read 220 greeting
        self::smtpCmd($socket, '', 220);

        $hostname = gethostname() ?: 'localhost';
        self::smtpCmd($socket, "EHLO {$hostname}", 250);
        self::smtpCmd($socket, 'STARTTLS', 220);

        // Enable TLS 1.2+
        $crypto = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
        if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
            $crypto |= STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
        }
        $result = stream_socket_enable_crypto($socket, true, $crypto);
        if ($result === false) {
            fclose($socket);
            throw new RuntimeException("SecurityMailer: TLS negotiation failed");
        }

        // Re-EHLO after STARTTLS
        self::smtpCmd($socket, "EHLO {$hostname}", 250);

        // AUTH LOGIN
        self::smtpCmd($socket, 'AUTH LOGIN', 334);
        self::smtpCmd($socket, base64_encode(self::SMTP_USER), 334);
        self::smtpCmd($socket, base64_encode(self::SMTP_PASS), 235);

        return $socket;
    }

    private static function smtpCmd($socket, string $command, int $expected): string
    {
        if ($command !== '') {
            $written = fwrite($socket, $command . "\r\n");
            if ($written === false) {
                throw new RuntimeException("SecurityMailer: write failed: {$command}");
            }
        }

        $response = '';
        while (true) {
            $line = fgets($socket, 512);
            if ($line === false) {
                throw new RuntimeException("SecurityMailer: read failed (expected {$expected})");
            }
            $response .= $line;
            if (strlen($line) >= 4 && $line[3] === ' ') break;
            if (strlen($line) < 4) break;
        }

        $actual = (int) substr($response, 0, 3);
        if ($actual !== $expected) {
            throw new RuntimeException("SecurityMailer: expected {$expected}, got {$actual}: " . trim($response));
        }
        return $response;
    }

    private static function sendMessage($socket, string $to, string $subject, string $body, bool $isHtml): void
    {
        $contentType = $isHtml ? 'text/html; charset=UTF-8' : 'text/plain; charset=UTF-8';
        $encodedFrom = mb_encode_mimeheader(self::FROM_NAME, 'UTF-8', 'B');
        $encodedSubject = mb_encode_mimeheader($subject, 'UTF-8', 'B');

        self::smtpCmd($socket, "MAIL FROM:<" . self::FROM_ADDRESS . ">", 250);
        self::smtpCmd($socket, "RCPT TO:<{$to}>", 250);
        self::smtpCmd($socket, 'DATA', 354);

        $headers = implode("\r\n", [
            "Date: " . date('r'),
            "From: {$encodedFrom} <" . self::FROM_ADDRESS . ">",
            "To: <{$to}>",
            "Subject: {$encodedSubject}",
            "MIME-Version: 1.0",
            "Content-Type: {$contentType}",
            "Content-Transfer-Encoding: quoted-printable",
            "X-Mailer: SecurityMailer/1.0",
        ]);

        $encodedBody = quoted_printable_encode($body);
        $message = $headers . "\r\n\r\n" . $encodedBody;

        self::smtpCmd($socket, $message . "\r\n.", 250);
        self::smtpCmd($socket, 'QUIT', 221);
    }
}
