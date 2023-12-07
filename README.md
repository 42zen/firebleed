# The Firebase Collider by [zen](https://linkedin.com/in/mathias-bochet)


## Overview
**Firebase Collider** is a powerful tool designed to identify vulnerabilities and assess security risks within Firebase projects. Leveraging its extensive feature set, the tool scans various [Firebase](https://firebase.google.com/) services, including [RealTime Database](https://firebase.google.com/docs/database), [Firestore Database](https://firebase.google.com/docs/firestore), [Firebase Storage](https://firebase.google.com/docs/storage), and [Firebase Hosting](https://firebase.google.com/docs/hosting), to provide comprehensive insights into project status, rules, and potential collisions with other services.


## Features
* Scan **Firebase RealTime Database** for project id, status, rules and content.
* Scan **Firestore Database** for status and rules.
* Scan **Firebase Storage** for status, rules and files.
* Scan **Firebase Hosting** V1 and V2 for status.
* Automatically find collisions with others services.
* Support **firebaseio.com** and **firebasedatabase.app** urls.


## Features In Development
- Support for **firestore.googleapis.com** urls.
- Support for **firebasestorage.googleapis.com** and **appspot.com** urls.
- Support for **firebaseapp.com** and **web.app** urls.
- Support for custom urls.


## Interestings Papers
- [Firebase Authentication](https://firebase.google.com/docs/auth): [manual authentication](https://j0vsec.com/post/firebase_during_bug_bounty_hunting/), [authentication shemes](https://time2hack.com/auth-schemes-in-google-firebase/), [authentication vulnerability](https://medium.com/swlh/google-firebase-authentication-vulnerability-245050cb7ceb) and [rest api](https://firebase.google.com/docs/reference/rest/auth).
- [Firebase Remote Config](https://firebase.google.com/docs/remote-config): [remote config dump](https://blog.deesee.xyz/android/automation/2019/08/03/firebase-remote-config-dump.html) and [rest api](https://firebase.google.com/docs/reference/remote-config/rest).
- [Firebase Machine Learning](https://firebase.google.com/docs/ml).
- [Firebase Cloud Functions](https://firebase.google.com/docs/functions).
- [Firebase Cloud Messaging](https://firebase.google.com/docs/cloud-messaging).
- [Brandon Evans Research](https://www.sans.org/white-papers/39885/).
- [Baserunner](https://iosiro.com/blog/baserunner-exploiting-firebase-datastores): [sources](https://github.com/iosiro/baserunner).
- Firebase Scanner: [by arxenix](https://github.com/arxenix/firebase-scanner), [by shivsahni](https://github.com/shivsahni/FireBaseScanner).
- [PyreBase](https://github.com/thisbejim/Pyrebase).
- [Firebase Enumeration](https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-services/gcp-databases-enum/gcp-firebase-enum).


## Getting Started
### Prerequisites
* Install [Python 3](https://www.python.org/downloads/).
* Install **requests** and **zipfile**:
```
pip install requests zipfile
```

### Install
To install firebase collider simply run the following command:
```
pip install firebase_collider
```
This will install the python library and the CLI tool.

### Verify Installation
To check if everything is installed start a new terminal and run the following command:
```
firebase_collider.py vulnerable-firebase
```
It should show some results ;)


## CLI Tool

### Usage
```
Usage: firebase_collider.py [OPTIONS] <url or apk or project>
```


### Options
* **-u** or **--urls-list** <filename>      : Scan a list of urls from a file
* **-a** or **--apks-list** <filename>      : Scan a list of apks from a file
* **-p** or **--projects-list** <filename>  : Scan a list of projects from a file
* **-f** or **--fast**                      : Do not check for infos or collisions
* **-d** or **--dump** <foldername>         : Dump all databases in a folder
* **-v** or **--verbose**                   : Enable all the debug messages


## Examples

### Scan an URL:
#### With CLI:
```
firebase_collider.py https://vulnerable-firebase-default-rtdb.firebaseio.com
```

#### With Python:
```
import firebase_collider

result = firebase_collider.scan_url("https://vulnerable-firebase-default-rtdb.firebaseio.com")
```

### Scan a project and dump all databases:
#### With CLI:
```
firebase_collider.py vulnerable-firebase -d results
```

#### With Python:
```
import firebase_collider

result = firebase_collider.scan_project("vulnerable-firebase", dump_folder="results")
```

### Scan an APK:
#### With CLI:
```
firebase_collider.py vulnerable_app.apk
```

#### With Python:
```
import firebase_collider

result = firebase_collider.scan_apk("vulnerable-firebase")
```

### Dump all databases from a list of URLs:
#### With CLI from a txt file:
```
firebase_collider.py -v -u list_of_urls.txt -d results
```

#### With CLI from a json file:
```
firebase_collider.py -v -u list_of_urls.json -d results
```


## Changelog
- **06/12/2023** - Initial script that can scan firebase project name for active services and scan firebase realtime database url for infos, status, rules and services collisions. The script handle firebase realtime database, firestore, firebase storage and firebase hosting.
