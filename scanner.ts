const axios = require('axios');
const Table = require('cli-table3');
const readline = require('readline');
const chalkModule = require('chalk');
const chalk = chalkModule.default || chalkModule;

interface HeaderCheck {
  name: string;
  status: 'PRESENT' | 'MISSING' | 'WEAK';
  value: string;
  risk: 'CRITICAL' | 'MAJOR' | 'MEDIUM' | 'MINOR' | 'SAFE';
  recommendation: string;
}

interface ScanResult {
  url: string;
  headers: HeaderCheck[];
  score: number;
  totalPoints: number;
  riskLevel: string;
}

const SECURITY_HEADERS: Record<string, { risk: 'CRITICAL' | 'MAJOR' | 'MEDIUM' | 'MINOR'; description: string }> = {
  'strict-transport-security': { risk: 'CRITICAL', description: 'Forces HTTPS connections' },
  'x-frame-options': { risk: 'CRITICAL', description: 'Prevents clickjacking attacks' },
  'x-content-type-options': { risk: 'MAJOR', description: 'Prevents MIME-type sniffing' },
  'content-security-policy': { risk: 'CRITICAL', description: 'Prevents XSS and injection attacks' },
  'access-control-allow-origin': { risk: 'MAJOR', description: 'Controls CORS policy' },
  'referrer-policy': { risk: 'MEDIUM', description: 'Controls referrer information' },
  'permissions-policy': { risk: 'MEDIUM', description: 'Controls browser features' },
  'x-xss-protection': { risk: 'MEDIUM', description: 'Legacy XSS protection' },
};

async function fetchHeaders(url: string): Promise<Record<string, string>> {
  try {
    const response = await axios.head(url, {
      timeout: 30000,
      validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
      maxRedirects: 5,
    });
    return response.headers as Record<string, string>;
  } catch (error: any) {
    throw new Error(`Failed to fetch headers from ${url}: ${error.message}`);
  }
}

function validateURL(url: string): string {
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = `https://${url}`;
  }
  return url;
}

function checkHeaders(headers: Record<string, string>): HeaderCheck[] {
  const checks: HeaderCheck[] = [];
  const lowerHeaders = Object.keys(headers).reduce(
    (acc, key) => {
      acc[key.toLowerCase()] = headers[key];
      return acc;
    },
    {} as Record<string, string>
  );

  Object.entries(SECURITY_HEADERS).forEach(([headerName, { risk, description }]) => {
    const value = lowerHeaders[headerName];

    if (value) {
      let status: 'PRESENT' | 'WEAK' = 'PRESENT';
      let headerRisk: 'CRITICAL' | 'MAJOR' | 'MEDIUM' | 'MINOR' | 'SAFE' = 'SAFE';

      if (headerName === 'strict-transport-security' && !value.includes('max-age')) {
        status = 'WEAK';
        headerRisk = 'MAJOR';
      }
      if (headerName === 'x-frame-options' && value.toLowerCase() === 'allow-from') {
        status = 'WEAK';
        headerRisk = 'MAJOR';
      }
      if (headerName === 'content-security-policy' && value === "'none'") {
        status = 'WEAK';
        headerRisk = 'MEDIUM';
      }
      if (headerName === 'access-control-allow-origin' && value === '*') {
        status = 'WEAK';
        headerRisk = 'MAJOR';
      }

      checks.push({
        name: headerName.toUpperCase(),
        status,
        value: value.substring(0, 50),
        risk: headerRisk,
        recommendation: `${description} – Value: ${value}`,
      });
    } else {
      checks.push({
        name: headerName.toUpperCase(),
        status: 'MISSING',
        value: 'N/A',
        risk,
        recommendation: `Missing: ${description}`,
      });
    }
  });

  return checks;
}

function calculateScore(checks: HeaderCheck[]): { score: number; total: number; level: string } {
  let totalPoints = 0;
  let earnedPoints = 0;

  const riskWeights: Record<string, number> = {
    CRITICAL: 30,
    MAJOR: 20,
    MEDIUM: 10,
    MINOR: 5,
    SAFE: 0,
  };

  checks.forEach((check) => {
    const weight = riskWeights[check.risk] || 0;
    totalPoints += weight;
    if (check.status === 'PRESENT' && check.risk === 'SAFE') {
      earnedPoints += weight;
    } else if (check.status === 'PRESENT') {
      earnedPoints += weight * 0.5;
    }
  });

  const percentage = Math.round((earnedPoints / totalPoints) * 100);
  let level = '';
  if (percentage >= 80) level = '✓ EXCELLENT';
  else if (percentage >= 60) level = '⚠ GOOD';
  else if (percentage >= 40) level = '⚠ MODERATE';
  else level = '✗ POOR';

  return { score: percentage, total: 100, level };
}

function displayResults(result: ScanResult): void {
  console.log('\n');
  console.log(chalk.bold.cyan('╔════════════════════════════════════════════════════╗'));
  console.log(chalk.bold.cyan(`║ SECURITY HEADER SCAN RESULTS                       ║`));
  console.log(chalk.bold.cyan(`║ URL: ${result.url.padEnd(43)}║`));
  console.log(chalk.bold.cyan('╚════════════════════════════════════════════════════╝'));
  console.log('\n');

  const table = new Table({
    head: [
      chalk.bold.white('Header'),
      chalk.bold.white('Status'),
      chalk.bold.white('Risk'),
      chalk.bold.white('Details'),
    ],
    style: { head: [], border: ['cyan'] },
    colWidths: [30, 12, 12, 40],
    wordWrap: true,
  });

  result.headers.forEach((header) => {
    const statusColor = header.status === 'PRESENT' ? chalk.green : chalk.red;
    const riskColor =
      header.risk === 'SAFE'
        ? chalk.green
        : header.risk === 'MINOR'
          ? chalk.yellow
          : header.risk === 'MEDIUM'
            ? chalk.yellowBright
            : chalk.red;

    table.push([
      chalk.bold(header.name),
      statusColor(header.status),
      riskColor(header.risk),
      header.recommendation,
    ]);
  });

  console.log(table.toString());
  console.log('\n');

  const scoreColor = result.score >= 80 ? chalk.green : result.score >= 60 ? chalk.yellow : chalk.red;
  console.log(chalk.bold.cyan('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log(
    chalk.bold(`SECURITY SCORE: ${scoreColor(`${result.score}/${result.totalPoints}`)} – ${result.riskLevel}`)
  );
  console.log(chalk.bold.cyan('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));

  const missingCritical = result.headers.filter((h) => h.status === 'MISSING' && h.risk === 'CRITICAL');
  if (missingCritical.length > 0) {
    console.log(chalk.red.bold(`\n⚠ CRITICAL MISSING HEADERS (${missingCritical.length}):`));
    missingCritical.forEach((h) => {
      console.log(chalk.red(`  • ${h.name}: ${h.recommendation}`));
    });
  }

  const weakHeaders = result.headers.filter((h) => h.status === 'WEAK');
  if (weakHeaders.length > 0) {
    console.log(chalk.yellow.bold(`\n⚠ WEAK CONFIGURATION (${weakHeaders.length}):`));
    weakHeaders.forEach((h) => {
      console.log(chalk.yellow(`  • ${h.name}: ${h.recommendation}`));
    });
  }

  console.log('\n');
}

async function main(): Promise<void> {
  let url = process.argv[2];

  if (!url) {
    console.log(chalk.bold.cyan('HTTP Security Header Scanner'));
    console.log(chalk.dim('Enter target URL (or press Ctrl+C to exit)\n'));
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    url = await new Promise((resolve) => {
      rl.question(chalk.yellow('Enter URL: '), (answer: string) => {
        rl.close();
        resolve(answer);
      });
    });
  }

  if (!url) {
    console.log(chalk.red('Error: URL is required'));
    process.exit(1);
  }

  try {
    const validatedUrl = validateURL(url);
    console.log(chalk.dim(`\nScanning ${validatedUrl}...\n`));

    const headers = await fetchHeaders(validatedUrl);
    const headerChecks = checkHeaders(headers);
    const { score, total, level } = calculateScore(headerChecks);

    const result: ScanResult = {
      url: validatedUrl,
      headers: headerChecks,
      score,
      totalPoints: total,
      riskLevel: level,
    };

    displayResults(result);

    if (score < 60) {
      process.exit(1);
    }
  } catch (error: any) {
    console.log(chalk.red.bold(`\n✗ ERROR: ${error.message}\n`));
    process.exit(1);
  }
}

main();