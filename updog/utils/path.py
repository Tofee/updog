import os
from OpenSSL import crypto
from math import log2
from time import ctime


def is_valid_subpath(relative_directory, base_directory):
    in_question = os.path.abspath(os.path.join(base_directory, relative_directory))
    return os.path.commonprefix([base_directory, in_question]) == base_directory


def is_valid_upload_path(path, base_directory):
    if path == '':
        return False
    in_question = os.path.abspath(path)
    return os.path.commonprefix([base_directory, in_question]) == base_directory


def get_relative_path(file_path, base_directory):
    return file_path.split(os.path.commonprefix([base_directory, file_path]))[1][1:]


def human_readable_file_size(size):
    # Taken from Dipen Panchasara
    # https://stackoverflow.com/questions/1094841/reusable-library-to-get-human-readable-version-of-file-size
    _suffixes = ['Bytes', 'KB',
    'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    order = int(log2(size) / 10) if size else 0
    return '{:.4g} {}'.format(size / (1 << (order * 10)), _suffixes[order])

#extentions to show in gallery mode
imageFileExtensions = ['.jpg','.jpeg','.gif','.bmp','.ico','.png']
#extentions to open as plain text
extentionsAsTxt = ['', '.log', '.txt', '.sh', '.ini', '.bat', '.py', '.sql', '.ps1']

def process_files(directory_files, base_directory, imageOnly=False):
    files = []
    for file in directory_files:
        relPath = get_relative_path(file.path, base_directory)
        if file.is_dir():
            size = '--'
            size_sort = -1
            canExecute = False
            canWrite = os.access(relPath, os.W_OK)
        else:
            if imageOnly:
                (filename, extension) = os.path.splitext(file.path)
                if extension.lower() not in imageFileExtensions:
                    continue
            size = human_readable_file_size(file.stat().st_size)
            size_sort = file.stat().st_size
            canExecute = os.access(relPath, os.X_OK)
            canWrite = os.access(relPath, os.W_OK)
        files.append({
            'name': file.name,
            'is_dir': file.is_dir(),
            'rel_path': relPath,
            'size': size,
            'size_sort': size_sort,
            'last_modified': ctime(file.stat().st_mtime),
            'last_modified_sort': file.stat().st_mtime,
            'can_execute': canExecute,
            'can_write': canWrite
        })
    return files


def getMime(path):
    (filename, extension) = os.path.splitext(path)
    if extension.lower() in extentionsAsTxt:
        return 'text/plain'
    else:
        return None



def sortFiles(i):
    return i['name']


def get_parent_directory(path, base_directory):
    difference = get_relative_path(path, base_directory)
    difference_fields = difference.split('/')
    if len(difference_fields) == 1:
        return ''
    else:
        return '/'.join(difference_fields[:-1])


def split_path(path, base_directory):
    if path == '' or path == '/' or path == base_directory:
        return [[''],[base_directory]]
    pathDic = []
    while 1:
        path, folder = os.path.split(path)
        
        pathDic.append(folder)
        # locations.append(folder)
        if path == base_directory or path == '' or path =='/':
            break
            
    pathDic.append(base_directory)
    locations=['/']
    pathDic.reverse()
    currentPath = ''
    # ignore the base directory
    x = 1
    while x < len(pathDic):
        currentPath += pathDic[x] + '/'
        locations.append('/'+currentPath)
        x += 1
    locations[len(locations)-1]=''
    return [locations,pathDic]
    

def create_self_signed_cert(certFile, keyFile, hostName):
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "PT"
    cert.get_subject().ST = "Portugal"
    cert.get_subject().L = "Portugal"
    cert.get_subject().O = "S-Razoes Lda"
    cert.get_subject().OU = "S-Razoes Lda"
    cert.get_subject().CN = hostName
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, b'sha512')

    open(certFile, "wt").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
    open(keyFile, "wt").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode('utf-8'))
