'use strict';
module.exports = {
  sqli: ["' OR '1'='1", '1;SELECT 1--', '"', '\\', '%27', "' UNION SELECT 1,2,3--"],
  sortAttacks: ['id;SELECT 1--', '(SELECT SLEEP(1))', 'name DESC, (SELECT 1)', '1 DESC--', 'id`'],
  nosql: [{ $ne: null }, { $gt: '' }, { $regex: '.*' }, ['a', 'b'], { $where: 'sleep(1)' }],
  ssrf: ['http://127.0.0.1/', 'http://localhost:22/', 'http://169.254.169.254/latest/meta-data/', 'file:///etc/passwd', 'http://[::1]/', 'http://0.0.0.0/'],
  redirects: ['https://evil.example', '//evil.example', 'https:evil.example', '/\\evil.example', 'javascript:alert(1)'],
  weakSecrets: ['secret', 'secret123', 'password', 'changeme', 'jwt_secret', '123456'],
};
