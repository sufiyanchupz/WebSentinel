# WebSentinel v1.0 - Test Cases

## Test Case 1: Target Reachability
- Target: http://127.0.0.1:8001
- Expected: HTTP 200 response
- Result: PASS

## Test Case 2: URL Discovery
- Expected: Discover the local lab pages
- Result: PASS
- Observed: / and /about.html

## Test Case 3: Technology Detection
- Expected: Detect server information
- Result: PASS
- Observed: SimpleHTTP/0.6 Python/3.14.7

## Test Case 4: Security Header Analysis
- Expected: Detect missing security headers
- Result: PASS

## Test Case 5: Sensitive Resource Exposure
- Target: Separate local lab
- Expected: No WebSentinel internal files exposed
- Result: PASS
- Observed: 0 potential exposures

## Test Case 6: Input and Parameter Analysis
- Expected: Detect HTML form and GET parameter
- Result: PASS
- Observed: 1 form and parameter "name"

## Test Case 7: Security Misconfiguration
- Expected: Identify configured observations
- Result: PASS
- Observed:
  - HTTP instead of HTTPS
  - Server banner disclosure

## Test Case 8: Risk Scoring
- Expected: Calculate weighted security score
- Result: PASS
- Observed: 45/100 on the current lab configuration

## Test Case 9: Evidence Collection
- Expected: Save scan evidence
- Result: PASS
- Files:
  - recon.txt
  - headers.txt
  - exposure.txt
  - misconfig.txt

## Test Case 10: Database Storage
- Expected: Save scan and findings in SQLite
- Result: PASS
- Latest verified Scan ID: 10

## Test Case 11: HTML Report
- Expected: Generate security assessment report
- Result: PASS
- Output: reports/report.html

## Test Case 12: Dashboard
- Expected: Display scan history and summary
- Result: PASS
- URL: http://127.0.0.1:5000

## Test Case 13: Scan Details
- Expected: Display individual scan information and findings
- Result: PASS
