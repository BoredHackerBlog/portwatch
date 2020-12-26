#search for CHANGEME
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

import datetime

import nmap3
nmap = nmap3.Nmap()

import schedule
import time

import threading

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////app/database/portwatch.db' #CHANGEME
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'asdflkajdsflkjasefiojel134234234'

db = SQLAlchemy(app)

admin = Admin(app)

class Asset(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(10),nullable=False)
    comment = db.Column(db.String(140))
    ips = db.Column(db.Text,nullable=False)

class OpenPorts(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    asset_name = db.Column(db.String(10),nullable=False)
    ip = db.Column(db.String(15),nullable=False)
    port = db.Column(db.Integer,nullable=False)

class OpenPortFinding(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    asset_name = db.Column(db.String(10),nullable=False)
    ip = db.Column(db.String(15),nullable=False)
    port = db.Column(db.Integer,nullable=False)
    timestamp = db.Column(db.DateTime,default=datetime.datetime.utcnow)

db.create_all()

admin.add_view(ModelView(Asset, db.session))
admin.add_view(ModelView(OpenPorts, db.session))
admin.add_view(ModelView(OpenPortFinding, db.session))

#add assets here and visit http://IP:PORT/asset_add to add the assets
db.session.add(Asset(name="server",comment="testing",ips="192.168.95.137, 10.0.0.30, 192.168.1.1/24")) #CHANGEME
db.session.commit()

#just scan top ports. Modify according to needs
def scan(ips):
    results = nmap.scan_top_ports(ips, args="--open -Pn -T5") #https://github.com/nmmapper/python3-nmap #CHANGEME
    results.pop('stats',None)
    results.pop('runtime',None)

    openports = {}
    for ip in results:
        openports[ip] = []
        for port in results[ip]['ports']:
            openports[ip].append(int(port['portid']))

    return openports

def initial_scan():
    assets = Asset.query.all()
    OpenPorts.query.delete()
    for asset in assets:
        ips_list = asset.ips.split(',')
        for ip in ips_list:
            scan_results = scan(ip)
            for scanned_ip in scan_results:
                for scanned_port in scan_results[scanned_ip]:
                    print(db.session.add(OpenPorts(asset_name=asset.name,ip=scanned_ip,port=scanned_port)))

    db.session.commit()
    return "Initial Scan finished"

def compare(asset, scan_results):
    compare_results = {}
    for scanned_ip in scan_results:
        for scanned_port in scan_results[scanned_ip]:
            if OpenPorts.query.filter_by(asset_name=asset.name,ip=scanned_ip,port=scanned_port).count() == 0:
                db.session.add(OpenPortFinding(asset_name=asset.name,ip=scanned_ip,port=scanned_port))
                if scanned_ip in compare_results.keys():
                    compare_results[scanned_ip].append(scanned_port)
                else:
                    compare_results[scanned_ip] = []
                    compare_results[scanned_ip].append(scanned_port)

    db.session.commit()
    return compare_results

def runscans():
    assets = Asset.query.all()
    for asset in assets:
        ips_list = asset.ips.split(',')
        for ip in ips_list:
            scan_results = scan(ip)
            compare_results = compare(asset, scan_results)
            #CHANGEME - do something with the compare_results variable if needed
    return "New scan finished"

#initial scan, rerunning this wipes baseline OpenPorts table and readds ports
@app.route("/initial_scan")
def initial_scan_page():
    return initial_scan()

#scan will result in comparision between initial scan results
@app.route("/new_scan")
def new_scan_page():
    return runscans()

#https://schedule.readthedocs.io/en/stable/
schedule.every(1).minutes.do(runscans) #CHANGEME

def schedule_thread():
    while True:
        schedule.run_pending()
        time.sleep(1)

schedule_thread_run = threading.Thread(target=schedule_thread, daemon=True)
schedule_thread_run.start()

if __name__ == '__main__':
    app.run(debug=False)
