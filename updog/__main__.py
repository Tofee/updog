import os
import signal
import argparse
import shutil
import zipfile
import tempfile
import ssl
import logging

from flask import Flask, flash, render_template, send_file, redirect, request, send_from_directory, url_for, abort
from flask_httpauth import HTTPBasicAuth
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.serving import run_simple

from updog.utils.path import is_valid_subpath, is_valid_upload_path, get_parent_directory, process_files, split_path, sortFiles, create_self_signed_cert, getMime
from updog.utils.output import error, info, warn, success
from updog import version as VERSION
from updog.utils.qrcode import ErrorCorrectLevel, QRCode
from updog.utils.utils import get_ip, register_service, get_service_info


def read_write_directory(directory):
    if os.path.exists(directory):
        if os.access(directory, os.W_OK and os.R_OK):
            return directory
        else:
            error('The output is not readable and/or writable')
    else:
        error('The specified directory does not exist')


def parse_arguments():
    parser = argparse.ArgumentParser(prog='updog')
    cwd = os.getcwd()
    parser.add_argument('--directory', metavar='DIRECTORY', type=read_write_directory, default=cwd,
                        help='Root directory\n'
                             '[Default=.]')
    parser.add_argument('--port', type=int, default=8090, help='Port to serve [Default=9090]')
    parser.add_argument('--password', type=str, default='', help='Use a password to access the page. (No username)')
    parser.add_argument('--file', type=str, default='', help='Restrict to serve specific file')
    parser.add_argument('-ssl', action='store_true', help='Use an encrypted ssl connection(TLS 1.2), if no public/private key pair is sent, one will be generated adhoc')
    parser.add_argument('--hostname', type=str, default='UPDogServer', help='Hostname to use when generating an adhoc SSL connection')
    parser.add_argument('--cert', type=str, default='', help='Location of certificate file to use as public key in SSL connections')
    parser.add_argument('--pKey', type=str, default='', help='Location of file to use as private key in SSL connections')
    parser.add_argument('-l', action='store_true', help='Use the UI lite version (cannot search or order columns)')
    parser.add_argument('-g', action='store_true', help='Allow gallery mode')
    parser.add_argument('-k', action='store_true', help='Allow user to kill server')
    parser.add_argument('-x', action='store_true', help='Allow executing files')
    parser.add_argument('-z', action='store_true', help='Allow zip directory')
    parser.add_argument('-u', action='store_true', help='Upload mode only')
    parser.add_argument('-m', action='store_true', help='Allow file modifications (delete, renames, duplicate, upload, create new folder)')
    parser.add_argument('-q', action='store_true', help='Show QR Code in terminal when ready')
    parser.add_argument('--mc', type=str, default='', help='Enable Multicast, name to cast')
    parser.add_argument('--logFile', type=str, default='', help='Log requests to file, file name')
    parser.add_argument('--version', action='version', version='%(prog)s v'+VERSION)

    args = parser.parse_args()

    # Normalize the path
    args.directory = os.path.abspath(args.directory)

    return args

def serveFile(path, attachment):
    mimetype = getMime(path)
    
    try:
        #TODO configurable response headers
        response = send_file(path, mimetype=mimetype, as_attachment=attachment)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
        #end of TODO
    except PermissionError:
        abort(403, 'Read Permission Denied!')
        

def zipdir(path, zipF, base="."):
    # zipF is zipfile handle
    if base == ".":
        base = path
    for root, dirs, files in os.walk(path):
        for file in files:
            zipF.write(os.path.join(root, file),arcname=os.path.join(root.replace(base, ""), file),compress_type = zipfile.ZIP_DEFLATED)
        for dir in dirs:
            zipdir(os.path.join(root,dir), zipF, base)


def main():
    args = parse_arguments()
    app = Flask(__name__)
    app.secret_key = os.urandom(16)
    auth = HTTPBasicAuth()
    global base_directory
    base_directory = args.directory

    fileToServe = ''
    if args.file:
        fileToServe = os.path.join(base_directory, args.file)

    # Deal with Favicon requests
    @app.route('/favicon.ico')
    def favicon():
        if fileToServe or args.l:
            return abort(500, 'No icon')
        return send_from_directory(os.path.join(app.root_path, 'static'),
                                   'images/favicon.ico', mimetype='image/vnd.microsoft.icon')
                                   
    
    
    ############################################
    # File Browsing and Download Functionality #
    ############################################
    @app.route('/', defaults={'path': None}, methods=['GET'])
    @app.route('/<path:path>', methods=['GET'])
    @auth.login_required
    def home(path, message=''):    
        #kill the server
        if args.k:
            if request.args.get('stop') is not None:
                print()
                error('User requested kill server!')

        #only upload 
        if args.u:
            return render_template('upload.html', version=VERSION, killable=args.k)

        #only serving a specific file option
        if fileToServe:
            return serveFile(fileToServe, False)
        
        
        # If there is a path parameter and it is valid
        if path and is_valid_subpath(path, base_directory):
            # Take off the trailing '/'
            path = os.path.normpath(path)
            requested_path = os.path.join(base_directory, path)

            # If directory
            if os.path.isdir(requested_path):
                back = get_parent_directory(requested_path, base_directory)
                is_subdirectory = True
                
                if args.z:
                    if request.args.get('zip') is not None:
                        tmp = tempfile.NamedTemporaryFile(mode='w+b', suffix='.zip',delete=True)
                        zipf = zipfile.ZipFile(tmp.name, 'w', zipfile.ZIP_DEFLATED)
                        zipdir(requested_path, zipf)
                        zipf.close()
                        
                        success('Directory zipped: %s' % requested_path)
                        
                        return serveFile(tmp.name, True)
            # If file
            elif os.path.isfile(requested_path):
                if args.z:
                    if request.args.get('zip') is not None:
                        tmp = tempfile.NamedTemporaryFile(mode='w+b', suffix='.zip',delete=True)
                        zipf = zipfile.ZipFile(tmp.name, 'w', zipfile.ZIP_DEFLATED)
                        zipf.write(requested_path,arcname=os.path.basename(requested_path),compress_type = zipfile.ZIP_DEFLATED)
                        zipf.close()
                        
                        success('File zipped: %s' % requested_path)
                        
                        return serveFile(tmp.name, True)

                # Check if the view flag is set
                if request.args.get('view') is None:
                    send_as_attachment = True
                else:
                    send_as_attachment = False
                    
                return serveFile(requested_path, send_as_attachment)

        else:
            # Root home configuration
            is_subdirectory = False
            requested_path = base_directory
            back = ''

        if os.path.exists(requested_path):
            # Read the files
            try:
                directory_files = process_files(os.scandir(requested_path), base_directory, imageOnly=(args.g and request.args.get('gallery') is not None))
            except PermissionError:
                abort(403, 'Read Permission Denied: ' + requested_path)
            
            homeHtml = 'home.html'
            if args.l:
                homeHtml = 'lite.html'
            
            if args.g:
                if request.args.get('gallery') is not None:
                    info('gallery mode')
                    homeHtml = 'gallery.html'
            pathsList = split_path(requested_path, base_directory)
            requested_path = requested_path.replace('\\', '/')
            return render_template(homeHtml, files=directory_files, back=back, galleryAllow=args.g,
                                   directory=requested_path, is_subdirectory=is_subdirectory, version=VERSION, killable=args.k, zipAllow=args.z, canExecute=args.x, canModify=args.m, paths=pathsList[1], directories=pathsList[0], len=len(pathsList[0]))
        else:
            return redirect('/')

    #################################################
    # Send message back and return to previous page #
    #################################################
    def returnWithMessage(message):
        flash(message)
        return redirect(request.referrer)

    ##############################
    # File Actions Functionality #
    ##############################
    @app.route('/fileAction', methods=['POST'])
    @auth.login_required
    def fileAction():
        #if it's upload only or server single file only, accept no file action
        if fileToServe or args.u:
            abort(403, 'Permission denied')
            
        if request.method == 'POST':
            if 'action' not in request.form or 'path' not in request.form:
                #invalid path or action
                return returnWithMessage('Invalid action.')
                
            filename = request.form['file']
            full_path = os.path.join(request.form['path'], filename)
            
            # Prevent access to paths outside of base directory
            if not is_valid_upload_path(request.form['path'], base_directory):
                flash('Not a valid path.')
                return redirect(request.referrer)
            
            full_path = os.path.realpath(full_path)
            
            if request.form['action'] == 'newFolder' and args.m:
                if not os.path.exists(full_path):
                    os.mkdir(full_path)
                    return returnWithMessage('Directory created')
                return returnWithMessage('Folder already exists with that name.')
            
            
            if not os.path.exists(full_path):
                abort(404, 'File not found: %s' % full_path)

            #execute the file
            if request.form['action'] == 'execute' and args.x:
                runCommand = 'sh ' + full_path
                if os.name == 'nt':
                    runCommand = 'start ' + full_path
                os.system(runCommand)
                flash('File executed.')
                return redirect(request.referrer)
            
            #allow file modifications
            if not args.m:
                flash('File modifications not allowed.')
                return redirect(request.referrer)
            
            #delete the file
            if request.form['action'] == 'delete':
                #if is file
                if os.path.isfile(full_path):
                    os.remove(full_path)
                else: #if is directory
                    shutil.rmtree(full_path)
                flash('Deleted.')
                return redirect(request.referrer)
            
            if 'newName' not in request.form:
                #no newName present
                flash('No new name added.')
                return redirect(request.referrer)
            
            #from this point on, needs new name
            if request.form['newName'] == '':
                #invalid newName
                flash('No new name returned.')
                return redirect(request.referrer)
                
            #options bellow expect field newName
            newfilename = secure_filename(request.form['newName'])
            new_full_path = os.path.join(request.form['path'], newfilename)
            
            if new_full_path == full_path:
                #same name, ignore
                flash('Same file?')
                return redirect(request.referrer)
            
            #rename the file to a new name
            if request.form['action'] == 'rename':
                shutil.move(full_path, new_full_path)
                flash('File renamed.')
                return redirect(request.referrer)
            
            #copy the file
            if request.form['action'] == 'copy':
                if os.path.isdir(full_path):
                    if os.path.isdir(new_full_path):
                        shutil.copytree(full_path,new_full_path)
                else:
                    if not os.path.isdir(new_full_path):
                        shutil.copyfile(full_path,new_full_path)
                flash('Copied file.')

            return redirect(request.referrer)

    #############################
    # File Upload Functionality #
    #############################
    @app.route('/upload', methods=['POST'])
    @auth.login_required
    def upload():
        if fileToServe:
            abort(403, 'Permission denied')
            
        #only if file modifications are allowed
        if not args.m and not args.u:
            info('Attempt to upload file withou permissions')
            return redirect(request.referrer)
            
        if request.method == 'POST':
            # No file part - needs to check before accessing the files['file']
            if 'file' not in request.files:
                return redirect(request.referrer)
                
            if 'path' not in request.form or request.form['path'] == '' or request.form['path'] == '.' or request.form['path'] == '/':
                path = base_directory
            else:
                path = request.form['path']
            # Prevent file upload to paths outside of base directory
            if not is_valid_upload_path(path, base_directory):
                return redirect(request.referrer)

            for file in request.files.getlist('file'):

                # No filename attached
                if file.filename == '':
                    return redirect(request.referrer)

                # Assuming all is good, process and save out the file
                if file:
                    filename = secure_filename(file.filename)
                    full_path = os.path.join(path, filename)
                    
                    #if it's upload UI only, and there's already a file with that name, change name
                    if args.u:
                        while os.path.exists(full_path):
                            filename = 'cp.' + filename
                            full_path = os.path.join(path, filename)

                    # if not Upload only then it assumes the user wanted to overwrite the file
                    try:
                        info('File upload: %s' % full_path)
                        file.save(full_path)
                        success('Uploaded')
                    except PermissionError:
                        abort(403, 'Write Permission Denied: ' + full_path)

            return redirect(request.referrer)

    # Password functionality is without username
    users = {
        '': generate_password_hash(args.password)
    }

    @auth.verify_password
    def verify_password(username, password):
        if args.password:
            if username in users:
                return check_password_hash(users.get(username), password)
            return False
        else:
            return True

    # Inform user before server goes up
    if fileToServe:
        if os.path.isfile(fileToServe):
            success('Serving file %s...' % fileToServe)
        else:
            error('File %s not found' % fileToServe)
    else:
        success('Serving {}...'.format(args.directory, args.port))

    #exit coded
    def handler(signal, frame):
        print()
        error('Exiting!')
    signal.signal(signal.SIGINT, handler)

    if args.q:
        localIp = get_ip() # '0.0.0.0'
    else:
        localIp = '0.0.0.0'
    
    ssl_context = None
    if args.ssl:
        if args.cert != '' and args.pKey != '':
            if not os.path.exists(args.pKey) or not os.path.exists(args.cert):
                print()
                error('Files provided as CERT or PrivKey do not exist')
            keyFile = args.pKey
            crtFile = args.cert
        else:
            certsPath = os.path.join(app.root_path, 'certs')
            
            crtFile = os.path.join(certsPath, 'local.crt')
            keyFile = os.path.join(certsPath, 'local.key')

            #on the first run, create the file
            if not os.path.exists(certsPath):
                os.mkdir(certsPath)
                hostName = args.hostname
                create_self_signed_cert(crtFile, keyFile, hostName)
                success('Certificates created for the first time for %s' % hostName)

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

        ssl_context.load_cert_chain(crtFile, keyFile)

        protocol = 'https://'
        url = protocol + localIp
        if args.port != 443:
            url = url + ":" + str(args.port)
    else:
        protocol = 'http://'
        url = protocol + localIp
        if args.port != 80:
            url = url + ":" + str(args.port)
    
    #show QRCode in console
    if args.q:
        qr = QRCode.getMinimumQRCode(url, ErrorCorrectLevel.M)
        qr.setErrorCorrectLevel(ErrorCorrectLevel.M)
        qr.make()
        qr.printQr()
        
    #multicast-dns
    if args.mc:
        infoMulticast = get_service_info(args.mc)
        if infoMulticast is None:
            register_service(args.mc, args.port)
            success('Registered Multicast ' + protocol + args.mc + '.local')
        else:
            error('Multicast ' + args.mc + ' already registered.')
    
    #handle logs
    logger = logging.getLogger('werkzeug')
    if args.logFile:
        fileHandlerLog = logging.FileHandler(args.logFile, 'w')
        logger.addHandler(fileHandlerLog)

    print(localIp + ' - ' + str(args.port))
    # localIp = '127.0.0.1'
    run_simple(localIp, args.port, app, ssl_context=ssl_context)


if __name__ == '__main__':
    main()
