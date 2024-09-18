# import library needed
import os
import sys
import json
import requests
import shutil
import subprocess
import string


# set the apktool settings
APKTOOL_FILENAME = 'apktool_2.9.1.jar'
APKTOOL_URL = f'https://bitbucket.org/iBotPeaches/apktool/downloads/{APKTOOL_FILENAME}'


# list all the firebases services
FIREBASE_REALTIME_DATABASE = "Firebase RealTime Database"
FIREBASE_FIRESTORE_DATABASE = "Firebase Firestore Database"
FIREBASE_STORAGE_DATABASE = "Firebase Storage Database"
FIREBASE_HOSTING = "Firebase Hosting"


# list of firebase realtime database domains
firebase_realtime_database_domains = [
    'firebaseio.com',
    'europe-west1.firebasedatabase.app',
    'asia-southeast1.firebasedatabase.app',
    'us-central1.firebasedatabase.app'
    'firebasedatabase.app',
]

# set the firebase firestore database url
firebase_firestore_database_domain = 'firestore.googleapis.com'
firebase_firestore_database_url = f"https://{firebase_firestore_database_domain}/v1"

# set the firebase storage database url
firebase_storage_database_domain = "firebasestorage.googleapis.com"
firebase_storage_database_url = f"https://{firebase_storage_database_domain}/v0/b"

# set the firebase hosting domain
firebase_hosting_v1_domain = 'firebaseapp.com'
firebase_hosting_v2_domain = 'web.app'

# set the firebase domains list
firebase_domains = firebase_realtime_database_domains + [
    firebase_firestore_database_domain,
    firebase_storage_database_domain,
    firebase_hosting_v1_domain,
    firebase_hosting_v2_domain
]


# set debug mode
DEBUG_MODE = True


# scan a url
def scan_url(url, verbose=False, fast_mode=False):

    # clean the url
    if url.startswith('http://') == False and url.startswith('https://') == False:
        url = 'https://' + url

    # find the service type
    service_type = find_service_from_url(url, verbose=verbose)

    # init the scan
    scan_results = []

    # build the scan process
    scan_processes = {
        FIREBASE_REALTIME_DATABASE: {
            'main_scanner': scan_realtime_database_from_url,
            'collision_scanners': [
                scan_firestore_database_from_project,
                scan_storage_database_from_project,
                scan_hosting_v1_from_project,
                scan_hosting_v2_from_project
            ]
        },
        FIREBASE_FIRESTORE_DATABASE: {
            'main_scanner': scan_firestore_database_from_url,
            'collision_scanners': [
                scan_realtime_database_from_project,
                scan_storage_database_from_project,
                scan_hosting_v1_from_project,
                scan_hosting_v2_from_project
            ]
        },
        FIREBASE_STORAGE_DATABASE: {
            'main_scanner': scan_storage_database_from_url,
            'collision_scanners': [
                scan_realtime_database_from_project,
                scan_firestore_database_from_project,
                scan_hosting_v1_from_project,
                scan_hosting_v2_from_project
            ]
        },
        FIREBASE_HOSTING: {
            'main_scanner': scan_hosting_from_url,
            'collision_scanners': [
                scan_realtime_database_from_project,
                scan_firestore_database_from_project,
                scan_storage_database_from_project
            ]
        }
    }

    # run the scan process
    if service_type in scan_processes:
        scan_process = scan_processes[service_type]
        scan_result = scan_process['main_scanner'](url, verbose=verbose, fast_mode=fast_mode)
        if scan_result is None:
            return []
        if scan_result['status'] != 'not found':
            scan_results += [ scan_result ]
        if fast_mode == False:
            project_id = scan_result['project_id']
            scan_results += scan_project(project_id, scan_functions=scan_process['collision_scanners'], verbose=verbose)

    # TODO: scan the url manually if needed
        # check if the ip is a google ip and which services is associated with this ip.
        # check for hosting from header. if YES: check for TXT record.
        # check the javascript code

    # return the scan results
    return scan_results

# scan a project
def scan_project(project_id, scan_functions=None, verbose=False):

    # init the scan
    scan_results = []
    if scan_functions is None:
        scan_functions = [
            scan_realtime_database_from_project,
            scan_firestore_database_from_project,
            scan_storage_database_from_project,
            scan_hosting_v1_from_project,
            scan_hosting_v2_from_project
        ]

    # scan the project
    for function in scan_functions:
        scan_result = function(project_id, verbose=verbose)
        if scan_result['status'] != 'not found':
            scan_results += [ scan_result ]

    # return the scan results
    return scan_results

# scan an apk file
def scan_apk(apk_path, verbose=False, fast_mode=False):
    
    # find the urls from the apk files
    urls = extract_urls_from_apk(apk_path, verbose=verbose)

    # TODO: find infos from 'google-services.json'

    # scan all the urls found
    scan_results = []
    for url in urls:
        scan_results += scan_url(url, verbose=verbose, fast_mode=fast_mode)

    # return the scan results
    return scan_results

# TODO: scan an ipa file

# extract firebase urls from an apk
def extract_urls_from_apk(apk_path, verbose=False):

    # download apktool if needed
    if os.path.exists(APKTOOL_FILENAME) == False:
        if verbose == True:
            print(f"[*] Downloading apktool...", end='', flush=True)
            response = requests.get(APKTOOL_URL)
            if response.status_code != 200:
                if verbose == True:
                    print("failure.")
                return None
            with open(APKTOOL_FILENAME, 'wb') as file:
                file.write(response.content)
            if verbose == True:
                print("success.")

    # disassemble the apk with apktool
    if verbose == True:
        print(f"[*] Disassembling app {apk_path}...", end='', flush=True)
    command = f"java -jar {APKTOOL_FILENAME} d -f -o tmp {apk_path}"
    result = subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode != 0:
        if verbose == True:
            print("failure.")
        return None
    files = []
    for foldername, subfolders, filenames in os.walk('tmp'):
        for filename in filenames:
            files += [ os.path.join(foldername, filename) ]
    files_count = len(files)
    if verbose == True:
        print(f"success: {files_count} files.")

    # find all firebases urls from the source
    if verbose == True:
        print(f"[*] Extracting firebases urls from the sources...       ", end='', flush=True)
        file_index = 0
    urls = []
    for file_path in files:
        if verbose == True:
            progress = "%-7s" % ("%0.2f%%" % (100 * file_index / files_count))
            print('\b' * 7 + progress, end='', flush=True)
            file_index += 1
        extracted_urls = extract_urls_from_file(file_path)
        for url in extracted_urls:
            if url not in urls:
                urls += [ url ]
    if verbose == True:
        print('\b' * 7 + f"done: {len(urls)} found.")

    # delete the folder
    shutil.rmtree('tmp')

    # return the urls
    return urls

# extract firebase urls from a file
def extract_urls_from_file(file_path):

    # find the encoding for the file
    encoding = find_file_encoding(file_path)
    if encoding is None:
        return []

    # search in the file for firebase domains
    extracts = {}
    with open(file_path, 'r', encoding=encoding) as file:
        for line_number, line in enumerate(file, start=1):
            for firebase_domain in firebase_domains:
                if firebase_domain in line:
                    extract = {
                        'path': file_path,
                        'line_number': line_number,
                        'line': line.strip()
                    }
                    if firebase_domain not in extracts:
                        extracts[firebase_domain] = [ extract ]
                    else:
                        extracts[firebase_domain] += [ extract ]

    # parse the extracted urls
    urls = []
    alphanumeric_characters = list(string.ascii_letters + string.digits)
    url_unreserved_characters = ['-', '_', '.', '~'] + alphanumeric_characters
    url_reserved_characters = [':', '/', '?', '#', '[', ']', '@', '%']
    url_allowed_characters = url_reserved_characters + url_unreserved_characters
    for firebase_domain in extracts:
        for extract in extracts[firebase_domain]:
            line = extract['line']
            line_size = len(line)
            pos = line.find(firebase_domain)
            for start_pos in range(pos - 1, 0, -1):
                if line[start_pos] in url_allowed_characters:
                    continue
                start_pos += 1
                break
            for stop_pos in range(pos + len(firebase_domain), line_size):
                if line[stop_pos] in url_allowed_characters:
                    continue
                break
            url = line[start_pos:stop_pos]
            if url not in urls:
                urls += [ url ]
    
    # return the urls list
    return urls

# find a file encoding
def find_file_encoding(file_path):

    encodings = [
        'cp1252',
        'utf-8',
        'ascii',
    ]

    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as file:
                for line_number, line in enumerate(file, start=1):
                    continue
            return encoding
        except UnicodeDecodeError:
            pass

    return None

# find the type of firebase service from a url
def find_service_from_url(url, verbose=False):

    # print logs
    if verbose == True:
        print("[*] Finding firebase service from url...", end='', flush=True)

    # create the service type
    service_type = None

    # check if this is a firebase realtime database
    for domain in firebase_realtime_database_domains:
        if url.find(domain) != -1:
            service_type = FIREBASE_REALTIME_DATABASE

    # check if this is a firebase firestore database
    if url.find(firebase_firestore_database_domain) != -1:
        service_type = FIREBASE_FIRESTORE_DATABASE

    # check if this is a firebase storage database
    if url.find(firebase_storage_database_domain) != -1 or url.find('.appspot.com') != -1:
        service_type = FIREBASE_STORAGE_DATABASE

    # check if the is a firebase hosting
    if url.find(firebase_hosting_v1_domain) != -1 or url.find(firebase_hosting_v2_domain) != -1:
        service_type = FIREBASE_HOSTING

    # print logs  
    if verbose == True:
        print(f"done: {service_type if service_type is not None else 'not a firebase url'}.")
        
    # service not found
    return service_type

# scan a firebase realtime database from an url
def scan_realtime_database_from_url(url, verbose=False, fast_mode=False):

    # scan the realtime database infos
    if fast_mode == False:
        if verbose == True:
            print("[*] Scanning realtime database infos...", end='', flush=True)
        project_id, database_id = None, None
        result = scan_realtime_database_infos(url)
        if result is not None:
            project_id, database_id = result
            if verbose == True:
                print(f"done: project is {project_id}, database is {database_id}.")
        else:
            if verbose == True:
                print("done: not found.")

    # guess the realtime database infos
    if result is None:
        if verbose == True:
            print("[*] Guessing realtime database infos...", end='', flush=True)
        result = guess_realtime_database_infos(url)
        if result is not None:
            project_id, database_id = result
            if verbose == True:
                print(f"done: project is {project_id}, database is {database_id}.")
        else:
            if verbose == True:
                print("done: not found.")

    # scan the realtime database status
    status, rules = scan_realtime_database_access(url, verbose=verbose)

    # return the scan result
    url = (url[:-1] if url[-1] == '/' else url) + '/.json'
    return {
        'url': url,
        'service': FIREBASE_REALTIME_DATABASE,
        'project_id': project_id,
        'database_id': database_id,
        'status': status,
        'rules': rules
    }

# scan a firebase realtime database from a project
def scan_realtime_database_from_project(project_id, verbose=False):

    # build the url
    database_id = project_id
    url = f"https://{database_id}.{firebase_realtime_database_domains[0]}"

    # scan the realtime database
    scan_result = scan_realtime_database_from_url(url, verbose=verbose)

    # also check for "default-rtdb" tag
    if scan_result['status'] == 'not found' and database_id.endswith("-default-rtdb") == False:
        database_id += "-default-rtdb"
        url = f"https://{database_id}.{firebase_realtime_database_domains[0]}"
        default_rtdb_scan_result = scan_realtime_database_from_url(url, verbose=verbose)
        if default_rtdb_scan_result['status'] != 'not found':
            return default_rtdb_scan_result

    # return the scan result
    return scan_result

# scan the project id and the database id from a realtime database
def scan_realtime_database_infos(url):

    # request the database console
    response = requests.get(url, allow_redirects=False)

    # check for console url
    if 'Location' not in response.headers or response.headers['Location'].startswith('https://console.firebase.google.com/project/') == False:
        return None
        
    # parse the console url
    console_ids = response.headers['Location'][44:-6].split('/database/')

    # return infos
    return (console_ids[0], console_ids[1])

# guess the project id and the database id from a realtime database
def guess_realtime_database_infos(url):

    # clean the url
    if url.startswith('http://') == True:
        url = url[7:]
    if url.startswith('https://') == True:
        url = url[8:]

    # find the firebase domain
    for domain in firebase_realtime_database_domains:
        pos = url.find(domain)
        if pos != -1:
            database_id = url[:pos - 1]
            project_id = database_id[:-13] if (database_id.endswith('-default-rtdb') == True) else database_id
            return (project_id, database_id)

    # couldn't find the domain
    return None

# scan the status and the rules from a realtime database
def scan_realtime_database_access(url, verbose=False):

    # scan the database status
    if verbose == True:
        print("[*] Scanning realtime database status...", end='', flush=True)
    status = scan_realtime_database_status(url)
    if verbose == True:
        print(f"done: {status}.")

    # redirect if needed
    if status.startswith('region redirect to ') == True:
        return scan_realtime_database_access(status[19:])

    # guess the rules
    if verbose == True:
        print("[*] Guessing realtime database rules...", end='', flush=True)
    rules = guess_realtime_database_rules(status)
    if verbose == True:
        print(f"done: {rules if rules is not None else 'unknown'}.")

    # return the scan result
    return (status, rules)

# scan the status of a firebase realtime database from a url
def scan_realtime_database_status(url):

    # request the database content
    url = (url[:-1] if url[-1] == '/' else url) + '/.json'
    response = requests.get(url, stream=True)
    content_length = int(response.headers['Content-Length'])

    # define the possible status
    status_finder = {
        'not found': {
            '{\n  "error" : "404 Not Found"\n}\n': 404
        },
        'temporary unavailable': {
            '{\n  "error" : "Firebase error. Please ensure that you have the URL of your Firebase Realtime Database instance configured correctly."\n}\n': 404
        },
        'permission denied': {
            '{\n  "error" : "Permission denied"\n}\n': 401
        },
        'missing appcheck token': {
            '{\n  "error" : "Missing appcheck token"\n}\n': 401
        },
        'payload is too large': {
            '{\n  "error" : "Payload is too large"\n}\n': 413
        },
        'invalid database name': {
            '{\n  "error" : "Invalid Firebase database name"\n}\n': 403
        },
        'internal error': {
            '{\n  "error" : "An internal error occurred"\n}\n': 500
        },
        'internal server error': {
            '{\n  "error" : "Internal server error."\n}\n': 504
        },
        'data requested exceeds the maximum size': {
            '{\n  "error" : "Data requested exceeds the maximum size that can be accessed with a single request."\n}\n': 400
        },
        'empty': {
            'null': 200
        }
    }

    # try to find the status
    for possible_status in status_finder:
        for possible_response in status_finder[possible_status]:
            if content_length == len(possible_response):
                if response.status_code == status_finder[possible_status][possible_response] and response.text == possible_response:
                    return possible_status

    # check for invalid results
    if content_length < 10000:
        if response.status_code != 200:

            # check for dynamic errors
            if response.text.find("The Firebase database \'") != -1:
                text = response.text[23:]
                pos = text.find("\' has ")
                text = text[pos + 6:]

                # check for deactivated
                if response.status_code == 423:
                    if text == "been deactivated.\"\n}\n":
                        return "deactivated"
                    
                    # check for disabled
                    if text == "been disabled by a database owner.\"\n}\n":
                        return "disabled"
                    
                # check for downgraded
                if response.status_code == 402:
                    if text == "be downgraded by a database owner. If you are an owner, consider upgrading.\"\n}\n":
                        return "downgraded"
                    
                    # check for quota limit exceeded
                    if text == "exceeded its quota limit and has been temporarily disabled. See https://firebase.google.com/support/faq/#database-overquota for more information.\"\n}\n":
                        return "quota limit exceeded"

            # check for region redirect
            text = '"error" : "Database lives in a different region. Please change your database URL to '
            if (content_length > len(text)) and (content_length < len(text) + 2048):
                pos = response.text.find(text)
                if response.status_code == 404 and pos != -1:
                    end_pos = response.text[pos+84:].find('"') + pos + 84
                    return f"region redirect to {response.text[pos+84:end_pos]}"

            # check for invalid token in path
            if response.text.find('"error" : "Invalid path: Invalid token in path"') != -1:
                return "protected"

            # unknown status
            if DEBUG_MODE == True:
                print("scan_realtime_database_status:", response.status_code, '\n', response.text, '\n')
            return "unknown status"
        
    # the database is public
    return f"{content_length} bytes"

# guess the rules of a firebase realtime database from a status
def guess_realtime_database_rules(status):

    # check for read=true rules
    read_true_status = ['payload is too large', 'data requested exceeds the maximum size', 'empty']
    if status.endswith('bytes of exposed datas') == True or status in read_true_status:
        return { 'read': True }

    # check for read=false rules
    read_false_status = ['permission denied', 'missing appcheck token']
    if status in read_false_status:
        return { 'read': False }
    
    # no rules
    return None

# dump a firebase realtime database
def dump_realtime_database(scan_result, dump_folder):
    if scan_result['status'].find(' bytes') != -1:
        with requests.get(scan_result['url'], stream=True) as response:
            dump_path = os.path.join(dump_folder, 'realtime-databases')
            try:
                os.mkdir(dump_path)
            except FileExistsError:
                pass
            file_path = os.path.join(dump_path, scan_result['database_id'] + '.json')
            with open(file_path, 'wb') as file:
                for chunk in response.iter_content(chunk_size=2048):
                    if chunk:
                        file.write(chunk)

# scan a firestore database from an url
def scan_firestore_database_from_url(url, verbose=False, fast_mode=False):
    
    # find project from url
    pos = url.find('/projects/')
    if pos == -1:
        return None
    project_id = url[pos + 10:]
    end_pos = project_id.find('/')
    if end_pos != -1:
        project_id = project_id[:end_pos]
    if len(project_id) == 0:
        return None
    
    # TODO: databases and documents are not parsed correctly
    
    # find database from url
    pos = url.find('/databases/')
    database_id = ''
    if pos != -1:
        database_id = url[pos + 11:]
        end_pos = database_id.find('/')
        if end_pos != -1:
            database_id = project_id[:end_pos]
    if len(database_id) == 0:
        return scan_firestore_database_from_project(project_id, verbose=verbose)
    
    # find collection from url
    pos = url.find('/documents/')
    collection_id = ''
    if pos != -1:
        collection_id = url[pos + 11:]
        end_pos = collection_id.find('/')
        if end_pos != -1:
            collection_id = project_id[:end_pos]
    if len(collection_id) == 0:
        return scan_firestore_database_from_project(project_id, database_id=database_id, verbose=verbose)
    
    # scan the specific collection
    return scan_firestore_database_from_project(project_id, database_id=database_id, collection_id=collection_id, verbose=verbose)

# scan a firestore database from a project
def scan_firestore_database_from_project(project_id, database_id=None, collection_id=None, verbose=False):
    
    # print logs
    if verbose == True:
        print(f"[*] Scanning firestore database...", end='', flush=True)

    # set the scan type
    public_not_empty = True if collection_id is None else False

    # build the firestore url
    database_id = "(default)" if database_id is None else database_id
    collection_id = "users" if collection_id is None else collection_id
    url_path = f"projects/{project_id}/databases/{database_id}"
    url = f"{firebase_firestore_database_url}/{url_path}/documents/{collection_id}"
        
    # request the database status
    response = requests.get(url)

    # create the rules
    rules = None

    # scan for status and rules
    if response.status_code == 200:
        if response.text == '{}\n':
            status = f'public' if public_not_empty == True else f'empty'
        else:
            status = f'{len(response.text)} bytes'
        rules = { 'read': True }
    elif response.status_code == 403 and response.text =='{\n  "error": {\n    "code": 403,\n    "message": "Missing or insufficient permissions.",\n    "status": "PERMISSION_DENIED"\n  }\n}\n':
        status = 'permission denied'
        rules = { 'read': False }
    elif response.status_code == 403 and response.text.startswith('{\n  "error": {\n    "code": 403,\n    "message": "Permission denied on resource project ') == True:
        status = 'not found'
    elif response.status_code == 403 and response.text.startswith('{\n  "error": {\n    "code": 403,\n    "message": "Cloud Firestore API has not been used in project ') == True:
        status = 'disabled'
    elif response.status_code == 404 and response.text == '{\n  "error": {\n    "code": 404,\n    "message": "The database %s does not exist for project %s Please visit https://console.cloud.google.com/datastore/setup?project=%s to add a Cloud Datastore or Cloud Firestore database. ",\n    "status": "NOT_FOUND"\n  }\n}\n' % (database_id, project_id, project_id):
        status = 'database not found'
    elif response.status_code == 400 and response.text == '{\n  "error": {\n    "code": 400,\n    "message": "The Cloud Firestore API is not available for Firestore in Datastore Mode database %s.",\n    "status": "FAILED_PRECONDITION"\n  }\n}\n' % url_path:
        status = 'datastore mode'
    else:
        status = 'unknown status'
        if DEBUG_MODE == True:
            print("scan_firestore_database_from_project:", response.status_code, '\n', response.text, '\n')
    
    # print logs
    if verbose == True:
        if rules is None:
            print(f"done: {status}.")
        else:
            print(f'done: status="{status}" and rules="{rules}".')

    # return the scan result
    scan_result = {
        'url': url,
        'service': FIREBASE_FIRESTORE_DATABASE,
        'project_id': project_id,
        'database_id': database_id,
        'collection_id': collection_id,
        'status': status,
        'rules': rules,
    }
    if rules != None:
        scan_result['rules'] = rules
    return scan_result

# dump a firestore database
def dump_firestore_database(scan_result, dump_folder):
    if scan_result['status'].find(' bytes') != -1:
        with requests.get(scan_result['url'], stream=True) as response:
            dump_path = os.path.join(dump_folder, 'firestore-databases')
            try:
                os.mkdir(dump_path)
            except FileExistsError:
                pass
            dump_path = os.path.join(dump_path, scan_result['project_id'])
            try:
                os.mkdir(dump_path)
            except FileExistsError:
                pass
            dump_path = os.path.join(dump_path, scan_result['database_id'])
            try:
                os.mkdir(dump_path)
            except FileExistsError:
                pass
            file_path = os.path.join(dump_path, scan_result['collection_id'] + '.json')
            with open(file_path, 'wb') as file:
                for chunk in response.iter_content(chunk_size=2048):
                    if chunk:
                        file.write(chunk)

# scan a firebase storage database from an url
def scan_storage_database_from_url(url, verbose=False, fast_mode=False):
    
    # find appspot from storage url
    pos = url.find(firebase_storage_database_domain + '/')
    if pos != -1:
        pos = url.find('/b/')
        if pos != -1:
            appspot_id = url[pos + 3:]
            end_pos = appspot_id.find('/')
            if end_pos != -1:
                appspot_id = appspot_id[:end_pos]
            if len(appspot_id) == 0:
                return None
            return scan_storage_database_from_appspot(appspot_id, verbose=verbose)

    # find project from appspot url
    pos = url.find('.appspot.com')
    if pos != -1:
        project_id = url[:pos]
        project_id = project_id.split('/')
        project_id = project_id[-1]
        return scan_storage_database_from_project(project_id, verbose=verbose)
    
    # didn't find anything to scan
    return None

# scan a firebase storage database from a project
def scan_storage_database_from_project(project_id, verbose=False):
    
    # guess the appspot id
    appspot_id = f"{project_id}.appspot.com"

    # scan the storage database
    return scan_storage_database_from_appspot(appspot_id, verbose=verbose)

# scan a firebase storage database from an appspot
def scan_storage_database_from_appspot(appspot_id, verbose=False):
    
    # print logs
    if verbose == True:
        print(f"[*] Scanning storage database...", end='', flush=True)

    # build the url
    url = f"{firebase_storage_database_url}/{appspot_id}/o/"
        
    # request the database status
    response = requests.get(url)

    # reset the permission
    rules = None

    # scan for status and permissions
    if response.status_code == 200:
        files_count = len(json.loads(response.text)['items'])
        status = f'{files_count} public files'
        rules = { 'read': True }
    elif response.status_code == 403 and response.text.find('Permission denied.') != -1:
        status = 'permission denied'
        rules = { 'read': False }
    elif response.status_code == 404 and response.text.find('Not Found.') != -1:
        status = 'not found'
    else:
        status = 'unknown status'
        if DEBUG_MODE == True:
            print("scan_storage_database_from_appspot:", response.status_code, '\n', response.text, '\n')
    
    # print logs
    if verbose == True:
        print(f"done: {status}.")

    # build the project id
    project_id = appspot_id
    pos = project_id.find('.')
    if pos != -1:
        project_id = project_id[:pos]

    # return the scan result
    return {
        'url': url,
        'service': FIREBASE_STORAGE_DATABASE,
        'appspot_id': appspot_id,
        'project_id': project_id,
        'status': status,
        'rules': rules,
    }

# dump a firebase storage database
def dump_storage_database(scan_result, dump_folder):
    if scan_result['status'].find(' public files') == True:
        response = requests.get(scan_result['url'])
        items = json.loads(response.text)['items']
        for item in items:
            url = f"https://{item['bucket']}/{item['name']}"
            with requests.get(url, stream=True) as response:
                dump_path = os.path.join(dump_folder, 'storage-databases')
                try:
                    os.mkdir(dump_path)
                except FileExistsError:
                    pass
                dump_path = os.path.join(dump_path, item['bucket'])
                try:
                    os.mkdir(dump_path)
                except FileExistsError:
                    pass
                file_path = os.path.join(dump_path, item['name'])
                with open(file_path, 'wb') as file:
                    for chunk in response.iter_content(chunk_size=2048):
                        if chunk:
                            file.write(chunk)

# scan a firebase hosting from an url
def scan_hosting_from_url(url, verbose=False, fast_mode=False):

    # clean the url from protocol
    if url.startswith('http://') == True:
        url = url[7:]
    if url.startswith('https://') == True:
        url = url[8:]
    
    # find project from url
    pos = url.find('.' + firebase_hosting_v1_domain)
    if pos != -1:
        project_id = url[:pos]
        return scan_hosting_v1_from_project(project_id, verbose=verbose)
    
    # find project from url
    pos = url.find('.' + firebase_hosting_v2_domain)
    if pos != -1:
        project_id = url[:pos]
        return scan_hosting_v2_from_project(project_id, verbose=verbose)
    
    # couldn't find any hosting domains
    return None

# scan a firebase hosting v1 from a project
def scan_hosting_v1_from_project(project_id, verbose=False):
    
    # print logs
    if verbose == True:
        print(f"[*] Scanning hosting v1...", end='', flush=True)

    # build the hosting url
    url = f"https://{project_id}.{firebase_hosting_v1_domain}"
        
    # request the database status
    response = requests.get(url)

    # scan for status
    if response.status_code == 200:
        status = 'active'
    elif response.status_code == 404 and response.text.startswith('\n<!doctype html>\n<html>\n  <head>\n    <title>Site Not Found</title>') == True:
        status = 'not found'
    else:
        status = 'unknown status'
        if DEBUG_MODE == True:
            print("scan_hosting_v1_from_project:", response.status_code, '\n', response.text, '\n')
    
    # print logs
    if verbose == True:
        print(f"done: {status}.")

    # return the scan result
    return {
        'url': url,
        'service': FIREBASE_HOSTING,
        'project_id': project_id,
        'status': status,
    }

# scan a firebase hosting v2 from a project
def scan_hosting_v2_from_project(project_id, verbose=False):
    
    # print logs
    if verbose == True:
        print(f"[*] Scanning hosting v2...", end='', flush=True)

    # build the hosting url
    url = f"https://{project_id}.{firebase_hosting_v2_domain}"
        
    # request the database status
    response = requests.get(url)

    # scan for status
    if response.status_code == 200:
        status = 'active'
    elif response.status_code == 404 and response.text.startswith('\n<!doctype html>\n<html>\n  <head>\n    <title>Site Not Found</title>') == True:
        status = 'not found'
    else:
        status = 'unknown status'
        if DEBUG_MODE == True:
            print("scan_hosting_v2_from_project:", response.status_code, '\n', response.text, '\n')
    
    # print logs
    if verbose == True:
        print(f"done: {status}.")

    # return the scan result
    return {
        'url': url,
        'service': FIREBASE_HOSTING,
        'project_id': project_id,
        'status': status,
    }


# settings class
class Settings:

    # create the parameters
    def parameters(self):
        return [
        {
            'name': 'urls-list',
            'code': 'u',
            'parameter': 'filename',
            'description': 'Scan a list of urls from a file',
            'function': self.parse_urls_list
        },
        {
            'name': 'projects-list',
            'code': 'p',
            'parameter': 'filename',
            'description': 'Scan a list of projects from a file',
            'function': self.parse_projects_list
        },
        {
            'name': 'apks-list',
            'code': 'a',
            'parameter': 'filename',
            'description': 'Scan a list of apks from a file',
            'function': self.parse_apks_list
        },
        {
            'name': 'fast',
            'code': 'f',
            'parameter': None,
            'description': 'Do not check for extra infos or collisions',
            'function': self.enable_fast_mode
        },
        {
            'name': 'dump-folder',
            'code': 'd',
            'parameter': 'filename',
            'description': 'Dump all databases in a folder',
            'function': self.set_dump_folder
        },
        {
            'name': 'quiet',
            'code': 'q',
            'parameter': None,
            'description': 'Disable all console messages',
            'function': self.disable_verbose
        },
        {
            'name': 'help',
            'code': 'h',
            'parameter': None,
            'description': 'Print this message',
            'function': self.print_usage
        }
    ]

    # create the settings object
    def __init__(self):
        self.target = None
        self.urls_list = None
        self.projects_list = None
        self.apks_list = None
        self.fast_mode = False
        self.dump_folder = None
        self.verbose = True

    # parse the parameters
    def parse(self, argc, argv):
        # check the number of arg
        if argc <= 1:
            return self.print_usage()
        
        # convert the argv to a list
        argl = []
        for arg in argv[1:]:
            argl += [ arg ]

        # parse all the list of arg
        i = 0
        while i < argc - 1:
            arg = argl[i]
            arg_found = False
            for parameter in self.parameters():
                if (arg == '-' + parameter['code']) or (arg == '--' + parameter['name']):
                    arg_found = True
                    if parameter['parameter'] is None:
                        if parameter['function']() == False:
                            return False
                    else:
                        i += 1
                        if i >= argc - 1:
                            print(f"Error: Missing {parameter['parameter']} for option {arg}.")
                            return self.print_usage()
                        if parameter['function'](argl[i]) == False:
                            return False
                    break
            i += 1
            if arg_found == False:
                if self.target is None:
                    self.target = arg
                else:
                    print(f"Error: Unknown option {arg}.")
                    return self.print_usage()

        # check if we have a target
        if self.target is None and self.urls_list is None and self.projects_list and self.apks_list is None:
            print(f"Error: No valid target to scan.")
            return False
        
        # parsing successfull
        return True
    
    # print the usage
    def print_usage(self):
        print("Usage: firebleed.py [OPTIONS] <url or apk or project>")
        print("OPTIONS:")
        for parameter in self.parameters():
            print("  -%s or --%-8s : %s" % (parameter['code'], parameter['name'], parameter['description']))
        return False
    
    # parse the urls list file
    def parse_urls_list(self, urls_list_path):

        # check if the file exist
        if os.path.exists(urls_list_path) == False:
            print(f"Error: urls list '{urls_list_path}' not found.")
            return False
        
        # try to load the file in json
        with open(urls_list_path, 'r') as file:
            try:
                urls_list = json.load(file)
            except json.decoder.JSONDecodeError:
                urls_list = None

        # try to load the file line by line
        if urls_list is None:
            urls_list = []
            with open(urls_list_path, 'r') as file:
                for line in file:
                    urls_list += [ line.strip() ]

        # save the urls list
        if urls_list != []:
            self.urls_list = urls_list
        return True
    
    # parse the projects list file
    def parse_projects_list(self, projects_list_path):

        # check if the file exist
        if os.path.exists(projects_list_path) == False:
            print(f"Error: projects list '{projects_list_path}' not found.")
            return False
        
        # try to load the file in json
        with open(projects_list_path, 'r') as file:
            try:
                projects_list = json.load(file)
            except json.decoder.JSONDecodeError:
                projects_list = None

        # try to load the file line by line
        if projects_list is None:
            projects_list = []
            with open(projects_list_path, 'r') as file:
                for line in file:
                    projects_list += [ line.strip() ]

        # save the projects list
        if projects_list != []:
            self.projects_list = projects_list
        return True
    
    # parse the apks list file
    def parse_apks_list(self, apks_list_path):

        # check if the file exist
        if os.path.exists(apks_list_path) == False:
            print(f"Error: apks list '{apks_list_path}' not found.")
            return False
        
        # try to load the file in json
        with open(apks_list_path, 'r') as file:
            try:
                apks_list = json.load(file)
            except json.decoder.JSONDecodeError:
                apks_list = None

        # try to load the file line by line
        if apks_list is None:
            apks_list = []
            with open(apks_list_path, 'r') as file:
                for line in file:
                    apks_list += [ line.strip() ]

        # save the apks list
        if apks_list != []:
            self.apks_list = apks_list
        return True
    
    # enable fast mode
    def enable_fast_mode(self):
        self.fast_mode = True
        return True
    
    # set the dump folder
    def set_dump_folder(self, dump_folder):
        try:
            os.mkdir(dump_folder)
        except FileExistsError:
            pass
        self.dump_folder = dump_folder
        return True
    
    # disable console message
    def disable_verbose(self):
        self.verbose = False
        return True


# main function
def main(argc, argv):

    # parse the settings
    settings = Settings()
    if settings.parse(argc, argv) == False:
        return 1
    target = settings.target
    verbose = settings.verbose
    fast_mode = settings.fast_mode
    dump_folder = settings.dump_folder

    # scan the target
    if target is not None:
        scan_results = scan_target(target, verbose=verbose, fast_mode=fast_mode)
        if scan_results is None:
            print(f"No firebases services found for '{target}'.")
        else:
            print_scan_results(scan_results)
            if dump_folder is not None:
                dump_databases(scan_results, dump_folder)

    # scan the list of urls
    if settings.urls_list is not None:
        for url in settings.urls_list:
            scan_results = scan_url(url, verbose=verbose, fast_mode=fast_mode)
            if scan_results == []:
                continue
            print_scan_results(scan_results)
            if dump_folder is not None:
                dump_databases(scan_results, dump_folder)

    # scan the list of projects
    if settings.projects_list is not None:
        for project in settings.projects_list:
            scan_results = scan_project(project, verbose=verbose)
            if scan_results == []:
                continue
            print_scan_results(scan_results)
            if dump_folder is not None:
                dump_databases(scan_results, dump_folder)

    # scan the list of apks
    if settings.apks_list is not None:
        for apk in settings.apks_list:
            scan_results = scan_apk(apk, verbose=verbose, fast_mode=fast_mode)
            if scan_results == []:
                continue
            print_scan_results(scan_results)
            if dump_folder is not None:
                dump_databases(scan_results, dump_folder)
    
    # end of process
    return 0

# scan a target
def scan_target(target, verbose=False, fast_mode=None):
    if target.endswith('.apk') == True:
        scan_results = scan_apk(target, verbose=verbose, fast_mode=fast_mode)
    elif target.find('.') != -1:
        scan_results = scan_url(target, verbose=verbose, fast_mode=fast_mode)
    else:
        scan_results = scan_project(target, verbose=verbose)
    
    # check if there is no result
    if scan_results == []:
        return None
    
    # return the scan results
    return scan_results

# dump the databases from a scan results
def dump_databases(scan_results, dump_folder):

    # dump all public databases
    for scan_result in scan_results:

        # dump realtime database
        if scan_result['service'] == FIREBASE_REALTIME_DATABASE:
            dump_realtime_database(scan_result, dump_folder)

        # dump firestore database
        if scan_result['service'] == FIREBASE_FIRESTORE_DATABASE:
            dump_firestore_database(scan_result, dump_folder)

        # dump storage database
        if scan_result['service'] == FIREBASE_STORAGE_DATABASE:
            dump_storage_database(scan_result, dump_folder)

# print a scan results
def print_scan_results(scan_results):
    print(f"\nProject: {scan_results[0]['project_id']}")
    for scan_result in scan_results:
        print(f"  %-28s : %-20s : %s" % (scan_result['service'], scan_result['status'], scan_result['url']))
    print("")


# run the cli
if __name__ == "__main__":
    exit(main(len(sys.argv), sys.argv))