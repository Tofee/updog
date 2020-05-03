import os
import signal
import argparse
import sys
import shutil
import zipfile
import tempfile

from flask import Flask, flash, render_template, send_file, redirect, request, send_from_directory, url_for, abort
from flask_httpauth import HTTPBasicAuth
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.serving import run_simple

from updog.utils.path import is_valid_subpath, is_valid_upload_path, get_parent_directory, process_files, split_path, sortFiles
from updog.utils.output import error, info, warn, success
from updog import version as VERSION

#extentions to open as plain text
extentionsAsTxt = ['', '.log', '.txt', '.sh', '.ini', '.bat', '.py', '.sql', '.ps1']

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
    parser.add_argument('-d', '--directory', metavar='DIRECTORY', type=read_write_directory, default=cwd,
                        help='Root directory\n'
                             '[Default=.]')
    parser.add_argument('-p', '--port', type=int, default=9090,
                        help='Port to serve [Default=9090]')
    parser.add_argument('--password', type=str, default='', help='Use a password to access the page. (No username)')
    parser.add_argument('-file', type=str, default='', help='Restrict to serve specific file')
    parser.add_argument('--ssl', action='store_true', help='Use an encrypted connection')
    parser.add_argument('-l', action='store_true', help='Use the UI lite version (cannot search or order columns)')
    parser.add_argument('-k', action='store_true', help='Allow user to kill server')
    parser.add_argument('-x', action='store_true', help='Allow executing files')
    parser.add_argument('-g', action='store_true', help='Allow gallery mode')
    parser.add_argument('-z', action='store_true', help='Allow zip directory')
    parser.add_argument('-m', action='store_true', help='Allow file modifications (delete, renames, duplicate, upload, create new folder)')
    parser.add_argument('--version', action='version', version='%(prog)s v'+VERSION)

    args = parser.parse_args()

    # Normalize the path
    args.directory = os.path.abspath(args.directory)

    return args

def serveFile(path, attachment):
    # Check if file extension
    (filename, extension) = os.path.splitext(path)
    if extension.lower() in extentionsAsTxt:
        mimetype = 'text/plain'
    else:
        mimetype = None
    
    try:
        return send_file(path, mimetype=mimetype, as_attachment=attachment)
    except PermissionError:
        abort(403, 'Read Permission Denied: ' + requested_path)
        

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
                        tmp = tempfile.NamedTemporaryFile(mode='w+b', suffix='.zip')#,delete=True)
                        zipf = zipfile.ZipFile(tmp.name, 'w', zipfile.ZIP_DEFLATED)
                        zipdir(requested_path, zipf)
                        zipf.close()
                        
                        success('File zipped: %s' % tmp.name)
                        
                        return serveFile(tmp.name, True)

            # If file
            elif os.path.isfile(requested_path):

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
                directory_files = process_files(os.scandir(requested_path), base_directory)
            except PermissionError:
                abort(403, 'Read Permission Denied: ' + requested_path)
            
            homeHtml = 'home.html'
            if args.l:
                homeHtml = 'lite.html'
            
            pathsList=split_path(requested_path, base_directory)
            #sorted(directory_files, key=sortFiles)
            return render_template(homeHtml, files=directory_files, back=back,
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
        if fileToServe:
            abort(403, 'Permission denied')
            
        if request.method == 'POST':
            if 'action' not in request.form or 'path' not in request.form:
                #invalid path or action
                return returnWithMessage('Invalid action.')
                
            filename = secure_filename(request.form['file'])
            full_path = os.path.join(request.form['path'], filename)
            
            # Prevent access to paths outside of base directory
            if not is_valid_upload_path(request.form['path'], base_directory):
                flash('Not a valid path.')
                return redirect(request.referrer)
            
            if request.form['action'] == 'newFolder' and args.m:
                if not os.path.exists(full_path):
                    os.mkdir(full_path)
                    return returnWithMessage('Directory created')
                return returnWithMessage('Folder already exists with that name.')
            
            if not os.path.exists(full_path):
                abort(404, 'File not found');

            #execute the file
            if request.form['action'] == 'execute' and args.x:
                os.system("%s" % full_path)
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
                    os.remove(full_path);
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
        if not args.m:
            return redirect(request.referrer)
            
        if request.method == 'POST':

            # No file part - needs to check before accessing the files['file']
            if 'file' not in request.files:
                return redirect(request.referrer)

            path = request.form['path']
            # Prevent file upload to paths outside of base directory
            if not is_valid_upload_path(path, base_directory):
                return redirect(request.referrer)

            for file in request.files.getlist('file'):

                # No filename attached
                if file.filename == '':
                    return redirect(request.referrer)

                # Assuming all is good, process and save out the file
                # This assumes the user wanted to overwrite the file
                if file:
                    filename = secure_filename(file.filename)
                    full_path = os.path.join(path, filename)
                    try:
                        file.save(full_path)
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

    ssl_context = None
    if args.ssl:
        ssl_context = 'adhoc'

    run_simple("0.0.0.0", int(args.port), app, ssl_context=ssl_context)


if __name__ == '__main__':
    main()
