-- Malicious User-agent activity
SELECT *
  FROM RAW.OKTA_LOGS
 WHERE PUBLISHED >= '2023-10-01'
     AND CLIENT_USER_AGENT_RAW_USER_AGENT ILIKE ANY ('%Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.3538.77 Safari/537.36%','%Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.7113.93 Safari/537.36%')
