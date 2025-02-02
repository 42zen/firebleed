<h1 align="center" style="display: inline-block;">
    <img src="./logo.png" alt="FireBleed" width="5%">
    FireBleed by <a href="https://linkedin.com/in/mathias-bochet">zen</a>
</h1>


## Overview
**FireBleed** is a powerful tool designed to identify vulnerabilities and assess security risks within Firebase projects. Leveraging its extensive feature set, the tool scans various [Firebase](https://firebase.google.com/) services, including [RealTime Database](https://firebase.google.com/docs/database), [Firestore Database](https://firebase.google.com/docs/firestore), [Firebase Storage](https://firebase.google.com/docs/storage), and [Firebase Hosting](https://firebase.google.com/docs/hosting), to provide comprehensive insights into project status, rules, and potential collisions with other services.

![firebleed](firebleed.png)

## Features
* Support **urls**, **project names** and **apk files** scanning.
* Automatically find **collisions** with others services.
* Scan **TXT Records** for project id.
* Scan **Firebase RealTime Database** for project id, status, rules and **content**.
* Scan **Firestore Database** for status, rules and **collections**.
* Scan **Firebase Storage** for status, rules and **files**.
* Scan **Firebase Hosting** V1 and V2 for status.
* Support **firebaseio.com** and **firebasedatabase.app** urls.
* Support **firestore.googleapis.com** urls.
* Support **firebasestorage.googleapis.com** and **appspot.com** urls.
* Support **firebaseapp.com** and **web.app** urls.


## Features In Development
- Support **website** in-depth scanning.
- Automatically find **api keys** from apks or websites.
- Access firebase services from **api keys**.
- Scan **Firebase Remote Config**.


## Getting Started
### Prerequisites
* Install [Python 3](https://www.python.org/downloads/).
* Install **requests** and **zipfile**:
```
pip install requests zipfile
```
* If you want to scan apk file you need install [Java](https://www.java.com/download/).

### Install
To install firebleed simply run the following command:
```
git clone https://github.com/42zen/firebleed
```
This should download the python script in a 'firebleed' folder.

### Verify Installation
To check if everything is installed start a new terminal, go to the firebleed folder, and run the following command:
```
python firebleed.py vulnerable-firebase
```
It should show some results ;)



## CLI Tool
### Usage
```
Usage: firebleed.py [OPTIONS] <url or apk or project>
```

### Options
|  Code  |        Name         | Parameter  |           Description                      |
|--------|---------------------|------------|--------------------------------------------|
| **-u** | **--urls-list**     | filename   | Scan a list of urls from a file            |
| **-a** | **--apks-list**     | filename   | Scan a list of apks from a file            |
| **-p** | **--projects-list** | filename   | Scan a list of projects from a file        |
| **-d** | **--dump**          | foldername | Dump all databases in a folder             |
| **-q** | **--quiet**         |            | Disable all console messages               |


## Examples

### Scan an URL:
#### With CLI:
```
python firebleed.py https://example.com
```

#### With Python:
```
import firebleed

result = firebleed.scan_url("https://example.com")
```

### Scan a project and dump all databases:
#### With CLI:
```
python firebleed.py vulnerable-firebase -d results
```

#### With Python:
```
import firebleed

result = firebleed.scan_project("vulnerable-firebase", dump_folder="results")
```

### Scan an APK:
#### With CLI:
```
python firebleed.py vulnerable_app.apk
```

#### With Python:
```
import firebleed

result = firebleed.scan_apk("vulnerable_app.apk")
```

### Dump all databases from a list of URLs:
#### With CLI from a txt file:
```
python firebleed.py -v -u list_of_urls.txt -d results
```

#### With CLI from a json file:
```
python firebleed.py -v -u list_of_urls.json -d results
```


## Interestings Papers
- [Firebase Authentication](https://firebase.google.com/docs/auth): [manual authentication by j0vsec](https://j0vsec.com/post/firebase_during_bug_bounty_hunting/), [authentication shemes by time2hack](https://time2hack.com/auth-schemes-in-google-firebase/), [authentication vulnerability by t0mstah](https://medium.com/swlh/google-firebase-authentication-vulnerability-245050cb7ceb) and [rest api](https://firebase.google.com/docs/reference/rest/auth).
- [Firebase Remote Config](https://firebase.google.com/docs/remote-config): [remote config dump by deesee](https://blog.deesee.xyz/android/automation/2019/08/03/firebase-remote-config-dump.html) and [rest api](https://firebase.google.com/docs/reference/remote-config/rest).
- [Firebase Machine Learning](https://firebase.google.com/docs/ml).
- [Firebase Cloud Messaging](https://firebase.google.com/docs/cloud-messaging).
- [Brandon Evans Research](https://www.sans.org/white-papers/39885/).
- Firebase Scanners: [by arxenix](https://github.com/arxenix/firebase-scanner), [by shivsahni](https://github.com/shivsahni/FireBaseScanner), [Baserunner](https://iosiro.com/blog/baserunner-exploiting-firebase-datastores) ([sources](https://github.com/iosiro/baserunner)).
- [PyreBase](https://github.com/thisbejim/Pyrebase).
- [Firebase Enumeration](https://cloud.hacktricks.xyz/pentesting-cloud/gcp-security/gcp-services/gcp-databases-enum/gcp-firebase-enum).


## Changelog
- **06/12/2023** - Initial script that can scan firebase project name for active services and scan firebase realtime database url for infos, status, rules and services collisions. The script handle firebase realtime database, firestore, firebase storage and firebase hosting.
- **11/12/2023** - Better scan logic for firebase realtime database project. Added support for firebase firestore database urls, firebase storage database urls, and firebase hosting urls. Added fast mode option.
- **12/12/2023** - Added dumping for realtime, storage, and firestore databases with dump folder option.
- **09/25/2024** - Removed fast mode. Added TXT records resolution.