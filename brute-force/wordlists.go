package bruteforce

// BuiltinUsernames provides preset username lists for common brute-force scenarios.
var BuiltinUsernames = map[string][]string{
	"common": {
		"admin", "root", "administrator", "test", "guest", "user",
		"oracle", "postgres", "mysql", "redis", "ftp", "sa", "pi",
		"ubuntu", "deploy", "nagios", "zabbix", "hadoop", "jenkins",
		"git", "tomcat", "www", "backup", "info", "operator",
	},
	"top10": {
		"admin", "root", "administrator", "test", "guest", "user",
		"oracle", "postgres", "sa", "pi",
	},
	"service": {
		"admin", "root", "ftp", "mysql", "postgres", "redis",
		"oracle", "mongodb", "mssql", "ssh", "www", "webmaster",
		"guest",
	},
}

// BuiltinPasswords provides preset password lists from weakest to more comprehensive.
var BuiltinPasswords = map[string][]string{
	"weak": {
		"", "123456", "password", "admin", "admin123", "12345678",
		"1234567890", "123456789", "111111", "888888", "000000",
		"666666", "qwerty", "abc123", "1q2w3e4r", "root", "test",
		"guest", "letmein", "welcome", "monkey", "dragon", "master",
		"superman", "admin@123", "Admin@123", "P@ssword1", "Aa123456",
	},
	"top10": {
		"123456", "password", "admin", "admin123", "root",
		"test", "12345678", "1234567890", "111111", "",
	},
	"top100": {
		"123456", "password", "admin", "admin123", "root", "test",
		"guest", "qwerty", "abc123", "111111", "000000", "888888",
		"666666", "123123", "1234", "12345", "1234567", "12345678",
		"123456789", "1234567890", "pass", "passwd", "master",
		"dragon", "baseball", "iloveyou", "monkey", "shadow",
		"sunshine", "princess", "welcome", "letmein", "football",
		"solo", "passw0rd", "1q2w3e", "1q2w3e4r", "zaq1zaq1",
		"1qaz2wsx", "admin@123", "Admin@123", "Admin123",
		"P@ssword", "P@ss123", "Aa123456", "Test@123",
		"cisco", "cisco123", "default", "system", "oracle",
		"postgres", "mysql", "redis", "tomcat", "jenkins",
		"admin1", "admin12", "admin1234", "admin12345",
		"administrator", "root123", "root1234", "rootroot",
		"toor", "alpine", "ubnt", "support", "changeme",
		"change_me", "temp", "temp1", "temp123", "public",
		"private", "pass123", "pass1234", "pass12345",
		"password1", "password123", "Password1", "Password123",
		"P@ssw0rd", "Pa$$w0rd", "12345678", "1234567890",
		"111111", "888888", "000000", "666666", "123123",
		"qwerty123", "abc123456", "iloveyou123",
		"letmein123", "welcome1", "monkey123", "dragon123",
		"", "test123", "user", "user123",
	},
}
