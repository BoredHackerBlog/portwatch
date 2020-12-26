# portwatch
Project that does a baseline port scan then does scheduled scans and adds findings to a table

# use case
I want to know if a new port is opened up for the assets I'm watching... Port can be opened up due to misconfiguration or malicious action

# technologies
- Python
- Flask
- Flask-SQLAlchemy
- Flask-Admin
- Python3-Nmap
- Python Schedule library
- Docker

# Running the project
- Clone the project
- Modify the code, look for #CHANGEME
- Install flask libraries and debian/ubuntu packages (see Dockerfile), run flask run command, Alternatively, look use docker, look at the Dockerfile comments

# Usage
- Your initial assets will be added automatically
- Assets, open ports, and findings can be seen at http://ip:port/admin
- Visit http://ip:port/initial_scan to start initial scan and add open ports (baseline). this might take a while. You can modify the code to scan right after assets are added as well.
- Visit http://ip:port/new_scan to do a scan and compare, or just let schedule code do automated scanning...

# Warning
- Not tested with large amount of assets
- There is no threading for scans that are running so scanning a lot of IPs may take a while
- webapp doesn't have password protection
- Docker image is kinda large
