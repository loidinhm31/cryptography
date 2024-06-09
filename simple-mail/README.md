```shell
openssl req -x509 -newkey rsa:4096 -keyout private.pem -out public.pem
```

mysql -h localhost -P 3306 --protocol=tcp -u root -p

CREATE USER 'mailadmin'@'%' IDENTIFIED BY '123456';

GRANT ALL PRIVILEGES ON maildb.* TO 'mailadmin'@'%';

