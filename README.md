![Version 1.53](http://img.shields.io/badge/version-v1.52-green.svg)
![Python 3.8](http://img.shields.io/badge/python-3.8-blue.svg)
[![MIT License](http://img.shields.io/badge/license-MIT%20License-blue.svg)](https://github.com/s-razoes/updog/blob/master/LICENSE)

<p>
  <img src="https://sc0tfree.squarespace.com/s/updog.png" width=85px alt="updog"/>
</p>

Updog is a replacement for Python's `SimpleHTTPServer`. 
It allows uploading, downloading, folder manipulation and executions via HTTP/S, 
can set ad hoc SSL certificates and use HTTP basic auth.

<p align="center">
  <img src="https://sc0tfree.squarespace.com/s/updog-screenshot.png" alt="Updog screenshot"/>
</p>

## Installation

Install using pip:

`pip3 install git+https://github.com/s-razoes/updog.git`

## Usage

`updog [-d DIRECTORY] [-p PORT] [--password PASSWORD] [--ssl]`

| Argument                            | Description                                        |
|-------------------------------------|----------------------------------------------------| 
| -d DIRECTORY, --directory DIRECTORY | Root directory [Default=.]                         | 
| -p PORT, --port PORT                | Port to serve [Default=9090]                       |
| --password PASSWORD                 | Use a password to access the page. (No username)   |
| -ssl                                | Enable transport encryption via SSL                |
| --hostname                          | Hostname to use when generating an adhoc SSL cert  |
| --cert                              | Certificate file to use as public key in SSL       |
| --pKey                              | Location of file to use as private key in SSL      |
| --version                           | Show version                                       |
| -k                                  | Killable server (from web)                         |
| -l                                  | Lite UI version                                    |
| -m                                  | Allow file modification (del, ren, copy, new dir)  |
| -x                                  | Allow file execution                               |
| -z                                  | Allow download of zipped folders                   |
| -g                                  | Allow gallery mode                                 |
| -f FILE                             | Serve only specific a file                         |
| -h, --help                          | Show help                                          |

## Examples

**Serve from your current directory:**

`updog`

**Serve from another directory:**

`updog -d /another/directory`

**Serve from port 1234:**

`updog -p 1234`

**Password protect the page:**

`updog --password examplePassword123!`

*Please note*: updog uses HTTP basic authentication.
To login, you should leave the username blank and just
enter the password in the password field.

**Use an SSL connection:**

`updog -ssl`
This is generate a certificate in the application path /certs/
These can be replaced or invoced in the bash like so:
`updog -ssl --cert [CRT FILE] --pKey [PRIVATE KEY FILE]`


**Lite version with kill button and can manipulate and execute files:**

`updog -l -k -m -x`




**TODO**
- ~~SSL: Accept certificates to use~~
- Hide full path option
- ~~Drag and drop (normal UI only)~~
- Select multiple files to:
  - Move (within this directory tree only)
  - Delete
  - ~~Download as a single zip file~~
- ~~Breadcrumbs for directory~~
-~~New: Drop files only UI~~
- Improve gallery mode
- ~~Fix: Order files by name (lite UI)~~
- logFile to dump info into
- ~~info to show in the webpage (like upload successful, or file deleted etc)~~
