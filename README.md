<p align="center">
  <img src="https://github.com/k1nd0ne/VolWeb/blob/main/.images_readme/title2.png" alt="VolWeb Title"/>
</p>

Volweb is a digtial forensic memory analysis platform. The goal of VolWeb is to improve the efficiency of memory forensics by providing a centralized, visual and enhanced platform for incident responders and digital forensics investigators.
VolWeb is based on volatility3, and this platform will evolve with the framework development.

![alt text](https://github.com/k1nd0ne/VolWeb/blob/main/.images_readme/investigation.png)


**Volweb is still in development and will evolve quickly.**
Update communications will be via twitter or by following this repo.

## Features ✅
The platform is currently supporting the following features:

- Investigation creation and dump upload
- IoC import
- IoC extraction with linked processes
- process tree
- process scan
- process dump
- process env
- process cmdline
- process privileges
- process dump
- network scan
- hashdump
- dlllist
- filescan
- Timeline Explorer
- malfind
- User Authentication
- User Management
- Automatic Report Generation


## Getting Started 🛠️
Volweb is fully dockerized and can be deployed in a production environment.
In order to deploy Volweb, you should follow these steps:

Clone the repository.

```
git clone https://github.com/k1nd0ne/VolWeb
```

Then, edit the **docker/volweb.env** file and add the secret information according to your need to the following fields:

```
 POSTGRES_USER=USER_HERE
 POSTGRES_PASSWORD=PASSWORD_HERE
 DJANGO_SECRET=SECRET_KEY_HERE
```

Next, add your ssl certificate into the **nginx/ssl** folder (generated via certbot or openssl for example) :
```
openssl genrsa > ./VolWeb/docker/nginx/ssl/privkey.pem
openssl req -new -x509 -key ./VolWeb/docker/nginx/ssl/privkey.pem > ./VolWeb/docker/nginx/ssl/fullchain.pem
```
**Don't forget to fill the different fields in the openssl certificate configuration. 
Make sure that the privkey and fullchain files respectively have the same name as the example above.**

Finally, build the docker and run it.
```
cd ./VolWeb/docker
docker-compose build
docker-compose up -d
```

The ngnix logs can be found in the **/ngnix/log** folder.

By default the admin account created will have the following credentials :

```
admin:password
```


## Reset

⚠️ This procedure will delete all the memory dumps, IOCs and database items and will reset the VolWeb platform ⚠️

```
cd ./VolWeb/docker
docker-compose down --rmi all --volumes
```

```
cd ./VolWeb/
find . -path "*/migrations/*.py" -not -name "__init__.py" -delete
find . -path "*/migrations/*.pyc"  -delete
```

## Important Note

The admin account cannot create analysis. Only use this account for analyst account creation and don't forget to change the password.
Create the analysts accounts via the Django administration panel -> https://[IP]/admin.

Don't forget to add the first and the last name of the analyst to be able to select him when creating an investigation.
![alt text](https://github.com/k1nd0ne/VolWeb/blob/main/.images_readme/Note.png)

## Issues ⚠️
If you have found an issue, please raise it.
I am performing 1 sprint every month to fix discovered bugs.

### Need to contact me?
Contact me at k1nd0ne@mail.com for any questions regarding this tool.

# Next Release goals
- Celery Task timeout in case of corrupted memory dump
- Bug Fix

# Global goals
- Code optimisation
- Docker optimisation
- Add missing modules to the windows memory analysis.
- Mac OS support
- Linux support
- Visual confirmation of what to not look (legit process highlight integration)
- Import multiple IOC from a CSV
- Export IOCs to a CSV for qualification and integration to Threat Intelligence Platforms
