# Como usar 83996352374
Inicie o MongoDB e no banco de dados local crie as seguintes collections:

```
links
users
```
Crie o seguinte item na collection users:

```
{
  'username': 'admin',
  'password': "$2b$12$Qs/7BdOfbAMtT8wc6TwOUeY6CzWdBfbCu63uZcYIMUbZDSXpBxLX2',
  'level': 4
}
```

Agora faça abra o terminal e digite:

```
pip install -r requirements.txt
python app.py
```
Faça login com:
```
admin
senha
```
