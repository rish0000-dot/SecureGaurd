describe('SAST Unit Tests', () => {
  it('should test SQLi', () => {
    const q = "SELECT * FROM users WHERE username = '" + req.query.username + "'";
    db.query(q);
  });

  it('should test XSS', () => {
    res.send("<div>" + req.query.name + "</div>");
  });

  it('should test Command Execution', () => {
    const { exec } = require('child_process');
    exec('ping ' + req.query.ip);
  });

  it('should test Path Traversal', () => {
    const fs = require('fs');
    fs.readFile(req.query.file);
  });

  it('should test Secret matching', () => {
    const password = 'test_suite_dummy_password_constant';
  });
});