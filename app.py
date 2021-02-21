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
scanner_mutex = threading.Lock()

import pandas as pd

import requests

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////app/database/portwatch.db' #CHANGEME
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'asdflkajdsflkjasefiojel134234234' #CHANGEME

db = SQLAlchemy(app)

admin = Admin(app)

class Asset(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(10),nullable=False)
    comment = db.Column(db.String(140))
    ips = db.Column(db.Text,nullable=False)

class OldServices(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    asset_name = db.Column(db.String(10),nullable=False)
    ip = db.Column(db.String(15),nullable=False)
    port = db.Column(db.Integer,nullable=False)
    name = db.Column(db.String(15),nullable=True)
    product = db.Column(db.String(50),nullable=True)
    version = db.Column(db.String(50),nullable=True)
    extrainfo = db.Column(db.String(50),nullable=True)

class NewServices(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    asset_name = db.Column(db.String(10),nullable=False)
    ip = db.Column(db.String(15),nullable=False)
    port = db.Column(db.Integer,nullable=False)
    name = db.Column(db.String(15),nullable=True)
    product = db.Column(db.String(50),nullable=True)
    version = db.Column(db.String(50),nullable=True)
    extrainfo = db.Column(db.String(50),nullable=True)

class ServiceChanges(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    asset_name = db.Column(db.String(10),nullable=False)
    ip = db.Column(db.String(15),nullable=False)
    port = db.Column(db.Integer,nullable=False)
    name = db.Column(db.String(15),nullable=True)
    product = db.Column(db.String(50),nullable=True)
    version = db.Column(db.String(50),nullable=True)
    extrainfo = db.Column(db.String(50),nullable=True)
    status = db.Column(db.String(7),nullable=False)
    timestamp = db.Column(db.DateTime,default=datetime.datetime.utcnow)

class Notify(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(10),nullable=False)
    url = db.Column(db.String(), nullable=False)
    comment = db.Column(db.String(140))

db.create_all()

admin.add_view(ModelView(Asset, db.session))
admin.add_view(ModelView(OldServices, db.session))
admin.add_view(ModelView(NewServices, db.session))
admin.add_view(ModelView(ServiceChanges, db.session))
admin.add_view(ModelView(Notify, db.session))

#add assets here and visit http://IP:PORT/asset_add to add the assets
db.session.add(Asset(name="server",comment="testing",ips="192.168.95.137, 10.0.0.30")) #CHANGEME
db.session.commit()

def notifier(service_info):
    notification_endpoints = Notify.query.all()
    if len(notification_endpoints) > 0:
        for endpoint in notification_endpoints:
            try:
                r = requests.post(endpoint.url, data=service_info, timeout=1)
            except:
                print("something wrong with sending data to ", endpoint.url)
            
#just scan top ports. Modify according to needs
def scan(ips):
    results = nmap.scan_top_ports(ips, args="--open -Pn -T5 -sV") #https://github.com/nmmapper/python3-nmap #CHANGEME
    results.pop('stats',None)
    results.pop('runtime',None)

    return results

def initial_scan():
    scanner_mutex.acquire()
    assets = Asset.query.all()
    OldServices.query.delete()
    NewServices.query.delete()
    db.session.commit()

    for asset in assets:
        ips_list = asset.ips.split(',')
        for ip in ips_list:
            scan_results = scan(ip)
            for scanned_ip in scan_results:
                for scanned_port in scan_results[scanned_ip]['ports']:
                    asset_name = asset.name
                    ip = scanned_ip
                    port = scanned_port['portid']
                    if 'name' in scanned_port['service'].keys():
                        name = scanned_port['service']['name']
                    else:
                        name = "NULL"

                    if 'product' in scanned_port['service'].keys():
                        product = scanned_port['service']['product']
                    else:
                        product = "NULL"
                    
                    if 'version' in scanned_port['service'].keys():
                        version = scanned_port['service']['version']
                    else:
                        version = "NULL"

                    if 'extrainfo' in scanned_port['service'].keys():
                        extrainfo = scanned_port['service']['extrainfo']
                    else:
                        extrainfo = "NULL"

                    db.session.add(NewServices(asset_name=asset_name,ip=ip,port=port,name=name,product=product,version=version,extrainfo=extrainfo))
    
    db.session.commit()
    scanner_mutex.release()

def compare():
    OldServicesdf = pd.read_sql(OldServices.query.statement, OldServices.query.session.bind).drop(columns=['id']) 
    NewServicesdf = pd.read_sql(NewServices.query.statement, NewServices.query.session.bind).drop(columns=['id']) 
    
    removeddf = OldServicesdf.merge(NewServicesdf, how = 'outer' ,indicator=True).loc[lambda x : x['_merge']=='left_only']
    addeddf = OldServicesdf.merge(NewServicesdf, how = 'outer' ,indicator=True).loc[lambda x : x['_merge']=='right_only']

    return removeddf, addeddf

def run_new_scan():
    scanner_mutex.acquire()
    OldServices.query.delete()
    df = pd.read_sql(NewServices.query.statement, NewServices.query.session.bind)
    df.to_sql(OldServices.__table__.name,OldServices.query.session.bind,if_exists='replace')
    NewServices.query.delete()
    db.session.commit()

    assets = Asset.query.all()
    for asset in assets:
        ips_list = asset.ips.split(',')
        for ip in ips_list:
            scan_results = scan(ip)
            for scanned_ip in scan_results:
                for scanned_port in scan_results[scanned_ip]['ports']:
                    asset_name = asset.name
                    ip = scanned_ip
                    port = scanned_port['portid']
                    if 'name' in scanned_port['service'].keys():
                        name = scanned_port['service']['name']
                    else:
                        name = "NULL"

                    if 'product' in scanned_port['service'].keys():
                        product = scanned_port['service']['product']
                    else:
                        product = "NULL"
                    
                    if 'version' in scanned_port['service'].keys():
                        version = scanned_port['service']['version']
                    else:
                        version = "NULL"

                    if 'extrainfo' in scanned_port['service'].keys():
                        extrainfo = scanned_port['service']['extrainfo']
                    else:
                        extrainfo = "NULL"

                    db.session.add(NewServices(asset_name=asset_name,ip=ip,port=port,name=name,product=product,version=version,extrainfo=extrainfo))

    db.session.commit()
    scanner_mutex.release()

    removeddf, addeddf = compare()
    
    if removeddf.shape[0] > 0:
        for line in removeddf.iloc:
            db.session.add(ServiceChanges(asset_name=line['asset_name'], ip=line['ip'], port=int(line['port']), name=line['name'], product=line['product'], version=line['version'], extrainfo=line['extrainfo'], status="REMOVED"))
            service_info = {'asset_name' : line['asset_name'],'ip' : line['ip'],'port' : int(line['port']),'name' : line['name'],'product' : line['product'],'version' : line['version'],'extrainfo' : line['extrainfo'],'status' : 'REMOVED' }
            notifier(service_info)

    if addeddf.shape[0] > 0:
        for line in addeddf.iloc:
            db.session.add(ServiceChanges(asset_name=line['asset_name'], ip=line['ip'], port=int(line['port']), name=line['name'], product=line['product'], version=line['version'], extrainfo=line['extrainfo'], status="ADDED"))
            service_info = {'asset_name' : line['asset_name'],'ip' : line['ip'],'port' : int(line['port']),'name' : line['name'],'product' : line['product'],'version' : line['version'],'extrainfo' : line['extrainfo'],'status' : 'ADDED' }
            notifier(service_info)
    
    db.session.commit()

#initial scan, rerunning this wipes baseline OpenPorts table and readds ports
@app.route("/initial_scan")
def initial_scan_page():
    if scanner_mutex.locked() == True:
        return "Scanner running already"
    else:
        scanner = threading.Thread(target=initial_scan)
        scanner.start()
        return "Scan started"

#scan will result in comparision between initial scan results
@app.route("/new_scan")
def new_scan_page():
    if scanner_mutex.locked() == True:
        return "Scanner running already"
    else:
        scanner = threading.Thread(target=run_new_scan)
        scanner.start()
        return "Scan started"

@app.route("/scan_status")
def scan_status():
    if scanner_mutex.locked() == True:
        return "Scanner running already"
    else:
        return "Scanner NOT running"

@app.route("/")
def index():
    return "Try /admin, /initial_scan, /new_scan, or /scan_status"

#https://schedule.readthedocs.io/en/stable/
schedule.every(8).hours.do(run_new_scan) #CHANGEME

def schedule_thread():
    while True:
        schedule.run_pending()
        time.sleep(1)

schedule_thread_run = threading.Thread(target=schedule_thread, daemon=True)
schedule_thread_run.start()

if __name__ == '__main__':
    app.run(debug=False)