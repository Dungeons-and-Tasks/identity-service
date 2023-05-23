# identity-service

### Dev

```
# Запускаем MySQL, для удобства в докере, все для Unix'ойdev. Остальным сочувствую
docker run --rm --name mysql -p 3306:3306 --network my_net -d -e MYSQL_ROOT_PASSWORD=keke mysql:latest

# Создаем БДшку
mysql -P 3306 --protocol=tcp -u root -p
#
create database <database>;

# Проводим инициализацию БДшки
make init

# Генерируем ключи для создания access_token
make create-keypair

# Запускаем сервер
make dev
```
